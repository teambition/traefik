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
	"github.com/containous/traefik/v2/pkg/middlewares/accesslog"
	"github.com/containous/traefik/v2/pkg/tracing"
	"github.com/opentracing/opentracing-go/ext"
)

const (
	typeName                  = "canary"
	headerAuth                = "Authorization"
	headerUA                  = "User-Agent"
	headerXCanary             = "X-Canary"
	headerXRequestID          = "X-Request-ID"
	defaultCacheSize          = 100000
	defaultExpiration         = time.Minute * 10
	defaultCacheCleanDuration = time.Minute * 20
)

// Should be subset of DNS-1035 label
// https://kubernetes.io/docs/concepts/overview/working-with-objects/names/
var validLabelReg = regexp.MustCompile(`^[a-z][0-9a-z-]{1,62}$`)

// Canary ...
type Canary struct {
	name                 string
	product              string
	uidCookies           []string
	addRequestID         bool
	canaryResponseHeader bool
	loadLabels           bool
	ls                   *LabelStore
	next                 http.Handler
}

// New returns a Canary instance.
func New(ctx context.Context, next http.Handler, cfg dynamic.Canary, name string) (*Canary, error) {
	logger := log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName))

	if cfg.Product == "" {
		return nil, fmt.Errorf("product name required for Canary middleware")
	}

	expiration := time.Duration(cfg.CacheExpiration)
	if expiration < time.Second {
		expiration = defaultExpiration
	}
	cacheCleanDuration := time.Duration(cfg.CacheCleanDuration)
	if cacheCleanDuration < time.Minute {
		cacheCleanDuration = defaultCacheCleanDuration
	}

	if cfg.MaxCacheSize < 10 {
		cfg.MaxCacheSize = defaultCacheSize
	}

	c := &Canary{
		name:                 name,
		next:                 next,
		product:              cfg.Product,
		uidCookies:           cfg.UIDCookies,
		loadLabels:           cfg.Server != "",
		addRequestID:         cfg.AddRequestID,
		canaryResponseHeader: cfg.CanaryResponseHeader,
	}
	if c.loadLabels {
		c.ls = NewLabelStore(logger, cfg, expiration, cacheCleanDuration)
	}
	logger.Infof("Add canary middleware: %v, %v, %v", cfg, expiration, cacheCleanDuration)
	return c, nil
}

// GetTracingInformation implements Tracable interface
func (c *Canary) GetTracingInformation() (string, ext.SpanKindEnum) {
	return c.name, tracing.SpanKindNoneEnum
}

func (c *Canary) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	c.processRequestID(rw, req)
	c.processCanary(rw, req)
	c.next.ServeHTTP(rw, req)
}

func (c *Canary) processRequestID(rw http.ResponseWriter, req *http.Request) {
	requestID := req.Header.Get(headerXRequestID)
	if c.addRequestID {
		if requestID == "" {
			requestID = generatorUUID()
			req.Header.Set(headerXRequestID, requestID)
		}
		rw.Header().Set(headerXRequestID, requestID)
	}

	if logData := accesslog.GetLogData(req); logData != nil {
		logData.Core["XRequestID"] = requestID
		logData.Core["UserAgent"] = req.Header.Get(headerUA)
	}
}

func (c *Canary) processCanary(rw http.ResponseWriter, req *http.Request) {
	info := &canaryHeader{}

	if !c.loadLabels {
		// just trust the canary header when work as internal gateway.
		info.fromHeader(req.Header, true)
	} else {
		// load user's labels and update to header when work as public gateway.
		info.fromHeader(req.Header, false)
		if info.label == "" {
			if cookie, _ := req.Cookie(headerXCanary); cookie != nil && validLabelReg.MatchString(cookie.Value) {
				info.label = cookie.Value
			}
		}

		info.product = c.product
		info.uid = extractUserID(req, c.uidCookies)

		if info.label == "" && info.uid != "" {
			labels := c.ls.MustLoadLabels(req.Context(), info.uid, req.Header.Get(headerXRequestID))
			for _, l := range labels {
				if info.client != "" && !l.MatchClient(info.client) {
					continue
				}
				if info.channel != "" && !l.MatchChannel(info.channel) {
					continue
				}
				info.label = l.Label
				break
			}
		}
		info.intoHeader(req.Header)
		if c.canaryResponseHeader {
			info.intoHeader(rw.Header())
		}
	}

	if logData := accesslog.GetLogData(req); logData != nil {
		logData.Core["UID"] = info.uid
		logData.Core["XCanary"] = req.Header.Values(headerXCanary)
	}
}

type userInfo struct {
	UID string `json:"uid"`
	Sub string `json:"sub"`
	ID  string `json:"id"`
}

func extractUserID(req *http.Request, uidCookies []string) string {
	jwToken := req.Header.Get(headerAuth)
	if jwToken != "" {
		if strs := strings.Split(jwToken, " "); len(strs) == 2 {
			jwToken = strs[1]
		}
	}

	uid := extractUserIDFromBase64(extractPayload(jwToken))
	if uid == "" && len(uidCookies) > 0 {
		for _, name := range uidCookies {
			if cookie, _ := req.Cookie(name); cookie != nil {
				if uid = extractUserIDFromBase64(extractPayload(cookie.Value)); uid != "" {
					return uid
				}
			}
		}
	}
	return uid
}

func extractPayload(s string) string {
	if s == "" {
		return s
	}
	strs := strings.Split(s, ".")
	switch len(strs) {
	case 3:
		return strs[1] // JWT token
	case 1:
		return strs[0]
	}
	return ""
}

func extractUserIDFromBase64(s string) string {
	if s == "" {
		return s
	}
	if i := strings.IndexRune(s, '='); i > 0 {
		s = s[:i] // remove padding
	}
	var b []byte
	var err error
	if strings.ContainsAny(s, "+/") {
		b, err = base64.RawStdEncoding.DecodeString(s)
	} else {
		b, err = base64.RawURLEncoding.DecodeString(s)
	}

	if len(b) > 0 {
		user := &userInfo{}
		if err = json.Unmarshal(b, user); err == nil {
			switch {
			case user.UID != "":
				return user.UID
			case user.Sub != "":
				return user.Sub
			case user.ID != "":
				return user.ID
			}
		}
	}
	return ""
}

type canaryHeader struct {
	label   string
	product string
	uid     string
	client  string
	channel string
	app     string
	version string
}

// uid and product will not be extracted
func (ch *canaryHeader) fromHeader(header http.Header, trust bool) {
	vals := header.Values(headerXCanary)
	for _, v := range vals {
		switch {
		case strings.HasPrefix(v, "label="):
			ch.label = v[6:]
		case trust && strings.HasPrefix(v, "product="):
			ch.product = v[8:]
		case trust && strings.HasPrefix(v, "uid="):
			ch.uid = v[4:]
		case strings.HasPrefix(v, "client="):
			ch.client = v[7:]
		case strings.HasPrefix(v, "channel="):
			ch.channel = v[8:]
		case strings.HasPrefix(v, "app="):
			ch.app = v[4:]
		case strings.HasPrefix(v, "version="):
			ch.version = v[8:]
		default:
			if len(vals) == 1 && validLabelReg.MatchString(v) {
				ch.label = v
			}
		}
	}
}

// label should not be empty
func (ch *canaryHeader) intoHeader(header http.Header) {
	if ch.label == "" {
		return
	}
	header.Set(headerXCanary, fmt.Sprintf("label=%s", ch.label))
	if ch.product != "" {
		header.Add(headerXCanary, fmt.Sprintf("product=%s", ch.product))
	}
	if ch.uid != "" {
		header.Add(headerXCanary, fmt.Sprintf("uid=%s", ch.uid))
	}
	if ch.client != "" {
		header.Add(headerXCanary, fmt.Sprintf("client=%s", ch.client))
	}
	if ch.channel != "" {
		header.Add(headerXCanary, fmt.Sprintf("channel=%s", ch.channel))
	}
	if ch.app != "" {
		header.Add(headerXCanary, fmt.Sprintf("app=%s", ch.app))
	}
	if ch.version != "" {
		header.Add(headerXCanary, fmt.Sprintf("version=%s", ch.version))
	}
}
