package canary

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/middlewares"
	"github.com/containous/traefik/v2/pkg/tracing"
	"github.com/opentracing/opentracing-go/ext"
)

const (
	labelKey = "X-Canary-Label"
	typeName = "canary"
)

// Canary ...
type Canary struct {
	name   string
	cookie string
	next   http.Handler
	ls     *labelStore
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

	expire, err := time.ParseDuration(cfg.Expire)
	if err != nil {
		return nil, fmt.Errorf("invalid expire for Canary middleware")
	}
	if expire < time.Minute {
		expire = time.Minute
	}

	ls := newLabelStore(cfg, logger, expire)
	return &Canary{name: name, cookie: cfg.Cookie, next: next, ls: ls}, nil
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

	label := ""
	if uid := c.extractUserID(req); uid != "" {
		labels := c.ls.mustLoad(req.Context(), uid, req.Header)
		if len(labels) > 0 {
			label = labels[0].Label
		}
	}
	req.Header.Set("labelKey", label)
	c.next.ServeHTTP(rw, req)
}

func (c *Canary) extractUserID(req *http.Request) string {
	jwToken := req.Header.Get("Authorization")
	if jwToken != "" {
		if strs := strings.Split(jwToken, " "); len(strs) == 2 {
			jwToken = strs[1]
		}
	}
	if jwToken == "" {
		jwToken = req.URL.Query().Get("access_token")
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
