package canary

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/middlewares"
	"github.com/containous/traefik/v2/pkg/tracing"
	"github.com/opentracing/opentracing-go/ext"
)

const (
	typeName                  = "canary"
	headerAuth                = "Authorization"
	headerUA                  = "User-Agent"
	headerXCanary             = "X-Canary"
	headerXRequestID          = "X-Request-ID"
	queryAccessToken          = "access_token"
	defaultCacheSize          = 100000
	defaultExpiration         = time.Minute * 10
	defaultCacheCleanDuration = time.Minute * 20
)

// Should be subset of DNS-1035 label
// https://kubernetes.io/docs/concepts/overview/working-with-objects/names/
var validLabelReg = regexp.MustCompile(`^[a-z][0-9a-z-]{1,62}$`)

// Canary ...
type Canary struct {
	name         string
	cookie       string
	addRequestID bool
	next         http.Handler
	ls           *labelStore
}

// New returns a Canary instance.
func New(ctx context.Context, next http.Handler, cfg dynamic.Canary, name string) (*Canary, error) {
	logger := log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName))
	logger.Debug("Add canary middleware")

	if cfg.Product == "" {
		return nil, fmt.Errorf("product name required for Canary middleware")
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("canary label server required for Canary middleware")
	}

	expiration := time.Duration(cfg.CacheExpiration)
	if expiration < time.Minute {
		expiration = defaultExpiration
	}
	cacheCleanDuration := time.Duration(cfg.CacheCleanDuration)
	if cacheCleanDuration < time.Minute {
		cacheCleanDuration = defaultCacheCleanDuration
	}

	if cfg.MaxCacheSize < 10 {
		cfg.MaxCacheSize = defaultCacheSize
	}

	ls := newLabelStore(cfg, logger, expiration, cacheCleanDuration)
	return &Canary{name: name, cookie: cfg.Cookie, addRequestID: cfg.AddRequestID, next: next, ls: ls}, nil
}

// GetTracingInformation implements Tracable interface
func (c *Canary) GetTracingInformation() (string, ext.SpanKindEnum) {
	return c.name, tracing.SpanKindNoneEnum
}

func (c *Canary) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// TODO Client and Channel
	// userAgent:"Teambition/11.2.1 (iPhone; iOS 13.3.1)"
	// userAgent:"Android/9 (OPPO PBET00;zh_CN) App/5.0.5 AliApp(DingTalk/5.0.5) com.alibaba.android.rimet/12726948 Channel/263200 language/zh-CN"
	// ua := uasurfer.Parse(req.Header.Get("User-Agent"))

	if c.addRequestID {
		addRequestID(req)
	}

	if label := req.Header.Get(headerXCanary); label == "" {
		if cookie, _ := req.Cookie(headerXCanary); cookie != nil {
			label = cookie.Value
		}

		if label != "" && !validLabelReg.MatchString(label) {
			label = ""
		}

		uid := c.extractUserID(req)
		if label == "" && uid != "" {
			labels := c.ls.mustLoad(req.Context(), uid, req.Header)
			if len(labels) > 0 {
				label = labels[0].Label
			}
		}

		if label != "" {
			req.Header.Set(headerXCanary, fmt.Sprintf("label=%s", label))
			req.Header.Add(headerXCanary, fmt.Sprintf("product=%s", c.ls.product))
			if uid != "" {
				req.Header.Add(headerXCanary, fmt.Sprintf("uid=%s", uid))
			}
		}
	}

	c.next.ServeHTTP(rw, req)
}

func (c *Canary) extractUserID(req *http.Request) string {
	jwToken := req.Header.Get(headerAuth)
	if jwToken != "" {
		if strs := strings.Split(jwToken, " "); len(strs) == 2 {
			jwToken = strs[1]
		}
	}
	if jwToken == "" {
		jwToken = req.URL.Query().Get(queryAccessToken)
	}
	if jwToken != "" {
		if strs := strings.Split(jwToken, "."); len(strs) == 3 {
			return extractUserIDFromBase64(strs[1])
		}
	} else if c.cookie != "" {
		if cookie, _ := req.Cookie(c.cookie); cookie != nil {
			return extractUserIDFromBase64(cookie.Value)
		}
	}
	return ""
}

type userInfo struct {
	UID string `json:"uid"`
}

func extractUserIDFromBase64(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
	}
	if err == nil {
		user := &userInfo{}
		if err = json.Unmarshal(b, user); err == nil {
			return user.UID
		}
	}
	return ""
}
