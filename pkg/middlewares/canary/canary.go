package canary

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/middlewares"
	"github.com/traefik/traefik/v2/pkg/middlewares/accesslog"
	"github.com/traefik/traefik/v2/pkg/server/cookie"
)

const (
	typeName                  = "canary"
	headerAuth                = "Authorization"
	headerUA                  = "User-Agent"
	headerXCanary             = "X-Canary"
	headerXRequestID          = "X-Request-Id"
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
	rateLimitKey         []string
	addRequestID         bool
	forwardLabel         bool
	canaryResponseHeader bool
	loadLabels           bool
	ls                   *LabelStore
	sticky               *dynamic.Sticky
	labelsMap            *dynamic.LabelsMap
	next                 http.Handler
}

// New returns a Canary instance.
func New(ctx context.Context, next http.Handler, cfg dynamic.Canary, name string) (*Canary, error) {
	logger := log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName))

	if cfg.Product == "" {
		return nil, fmt.Errorf("product name required for canary middleware")
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

	if cfg.LabelsMap != nil {
		if cfg.LabelsMap.RequestHeaderName == "" || len(cfg.LabelsMap.Labels) == 0 {
			cfg.LabelsMap = nil
		}
	}

	c := &Canary{
		name:                 name,
		next:                 next,
		product:              cfg.Product,
		uidCookies:           cfg.UIDCookies,
		rateLimitKey:         cfg.RateLimitKey,
		loadLabels:           cfg.Server != "",
		addRequestID:         cfg.AddRequestID,
		forwardLabel:         cfg.ForwardLabel,
		canaryResponseHeader: cfg.CanaryResponseHeader,
		sticky:               cfg.Sticky,
		labelsMap:            cfg.LabelsMap,
	}

	if cfg.Sticky != nil {
		c.sticky.Cookie.Name = cookie.GetName(cfg.Sticky.Cookie.Name, name)
		if !strSliceHas(c.uidCookies, c.sticky.Cookie.Name) {
			c.uidCookies = append(c.uidCookies, c.sticky.Cookie.Name)
		}
	}

	if c.loadLabels {
		c.ls = NewLabelStore(logger, cfg, expiration, cacheCleanDuration, name)
	}
	logger.Debugf("Add canary middleware: %v, %v, %v", cfg, expiration, cacheCleanDuration)
	return c, nil
}

// GetTracingInformation implements Tracable interface
func (c *Canary) GetTracingInformation() (string, ext.SpanKindEnum) {
	return c.name, ext.SpanKindRPCClientEnum
}

func (c *Canary) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	c.processRequestID(rw, req)
	c.processCanary(rw, req)
	c.next.ServeHTTP(rw, req)
}

func (c *Canary) processRequestID(rw http.ResponseWriter, req *http.Request) {
	requestID := req.Header.Get(headerXRequestID)
	if requestID == "" {
		requestID = req.Header.Get("X-CA-Request-Id")
	}
	if requestID == "" {
		requestID = req.Header.Get("Request-Id")
	}
	if c.addRequestID {
		if requestID == "" {
			// extract trace-id as x-request-id
			// https://www.w3.org/TR/trace-context/#traceparent-header
			if traceparent := req.Header.Get("traceparent"); len(traceparent) >= 55 {
				requestID = traceparent[3:35]
			} else if traceid := req.Header.Get("eagleeye-traceid"); len(traceid) > 0 {
				requestID = traceid
			} else {
				requestID = generatorUUID()
			}
			req.Header.Set(headerXRequestID, requestID)
		}
		rw.Header().Set(headerXRequestID, requestID)
	}

	if span := opentracing.SpanFromContext(req.Context()); span != nil {
		span.SetTag("component", "Canary")
		span.SetTag("x-request-id", requestID)
	}

	if logData := accesslog.GetLogData(req); logData != nil {
		logData.Core["XRealIp"] = req.Header.Get("X-Real-Ip")
		logData.Core["XRequestID"] = requestID
		logData.Core["UserAgent"] = req.Header.Get(headerUA)
		logData.Core["Referer"] = req.Header.Get("Referer")
		if traceparent := req.Header.Get("traceparent"); traceparent != "" {
			logData.Core["Traceparent"] = traceparent
		}
	}
}

func (c *Canary) processCanary(rw http.ResponseWriter, req *http.Request) {
	info := &canaryHeader{}

	if c.forwardLabel {
		// just trust the canary header when work as internal gateway.
		info.fromHeader(req.Header, true)
	} else {
		// load user's labels and update to header when work as public gateway.
		info.fromHeader(req.Header, false)

		// try load labels from cookie when not exists in request X-Canary header.
		if info.label == "" {
			if cookie, _ := req.Cookie(headerXCanary); cookie != nil && cookie.Value != "" {
				info.feed(strings.Split(cookie.Value, ","), false)
			}
		}

		// try load labels from config with header when not exists.
		if info.label == "" && c.labelsMap != nil {
			key := req.Header.Get(c.labelsMap.RequestHeaderName)
			if vals := c.labelsMap.Labels[key]; vals != "" {
				info.feed(strings.Split(vals, ","), false)
			}
		}

		info.product = c.product
		info.uid = extractUserID(req, c.uidCookies)

		// anonymous user
		if info.uid == "" && c.sticky != nil {
			addr := req.Header.Get("X-Real-Ip")
			if addr == "" {
				addr = req.Header.Get("X-Forwarded-For")
			}
			if addr == "" {
				addr, _, _ = net.SplitHostPort(req.RemoteAddr)
			}
			info.uid = anonymousID(addr, req.Header.Get(headerUA), req.Header.Get("Cookie"), time.Now().Format(time.RFC822))
			c.addSticky(info.uid, rw)
		}

		// try load labels from server
		if c.loadLabels && info.label == "" && info.uid != "" {
			labels := c.ls.MustLoadLabels(req.Context(), info.uid, req.Header.Get(headerXRequestID))
			for _, l := range labels {
				if !l.MatchClient(info.client) {
					continue
				}
				if !l.MatchChannel(info.channel) {
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

	rateLimitKey := ""
	if len(c.rateLimitKey) > 0 {
		keys := make([]string, 0, len(c.rateLimitKey))
		for _, k := range c.rateLimitKey {
			switch k {
			case "UID":
				keys = append(keys, info.uid)
			case "Method":
				keys = append(keys, req.Method)
			case "Path":
				keys = append(keys, req.URL.Path)
			case "Host":
				keys = append(keys, req.Host)
			default:
				if v := req.Header.Get(k); v != "" {
					keys = append(keys, v)
				}
			}
		}
		if len(keys) == 0 {
			if v := req.Header.Get("X-Real-Ip"); v != "" {
				keys = append(keys, v)
			} else if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				keys = append(keys, clientIP)
			} else {
				keys = append(keys, req.URL.String())
			}
		}
		rateLimitKey = strings.Join(keys, ":")
		req.Header.Set("X-Ratelimit-Key", rateLimitKey)
	}

	if logData := accesslog.GetLogData(req); logData != nil {
		logData.Core["UID"] = info.uid
		logData.Core["XCanary"] = info.String()
		if rateLimitKey != "" {
			logData.Core["XRateLimitKey"] = rateLimitKey
		}
	}
}

func (c *Canary) addSticky(id string, rw http.ResponseWriter) {
	if data, err := json.Marshal(userInfo{UID5: id}); err == nil {
		http.SetCookie(rw, &http.Cookie{
			Name:     c.sticky.Cookie.Name,
			Value:    base64.RawURLEncoding.EncodeToString(data),
			Path:     "/",
			MaxAge:   60 * 60 * 24 * 7,
			Secure:   c.sticky.Cookie.Secure,
			HttpOnly: c.sticky.Cookie.HTTPOnly,
			SameSite: convertSameSite(c.sticky.Cookie.SameSite),
		})
	}
}

type userInfo struct {
	UID0 string `json:"uid,omitempty"`
	UID1 string `json:"_userId,omitempty"`
	UID2 string `json:"userId,omitempty"`
	UID3 string `json:"user_id,omitempty"`
	UID4 string `json:"sub,omitempty"`
	UID5 string `json:"id,omitempty"`
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
			case user.UID0 != "":
				return user.UID0
			case user.UID1 != "":
				return user.UID1
			case user.UID2 != "":
				return user.UID2
			case user.UID3 != "":
				return user.UID3
			case user.UID4 != "":
				return user.UID4
			case user.UID5 != "":
				return user.UID5
			}
		}
	}
	return ""
}

// Canary Header specification, reference to https://www.w3.org/TR/trace-context/#tracestate-header
// X-Canary: label=beta,nofallback
// X-Canary: client=iOS,channel=stable,app=teambition,version=v10.0
// full example
// X-Canary: label=beta,product=urbs,uid=5c4057f0be825b390667abee,client=iOS,channel=stable,app=teambition,version=v10.0,nofallback,testing
// support fields: label, product, uid, client, channel, app, version, nofallback, testing
type canaryHeader struct {
	label      string
	product    string
	uid        string
	client     string
	channel    string
	app        string
	version    string
	nofallback bool
	testing    bool
}

// uid and product will not be extracted
// standard
// X-Canary: label=beta,product=urbs,uid=5c4057f0be825b390667abee,nofallback ...
// and compatible with
// X-Canary: beta
// or
// X-Canary: label=beta; product=urbs; uid=5c4057f0be825b390667abee; nofallback ...
// or
// X-Canary: label=beta
// X-Canary: product=urbs
// X-Canary: uid=5c4057f0be825b390667abee
// X-Canary: nofallback
func (ch *canaryHeader) fromHeader(header http.Header, trust bool) {
	vals := header.Values(headerXCanary)
	if len(vals) == 1 {
		if strings.IndexByte(vals[0], ',') > 0 {
			vals = strings.Split(vals[0], ",")
		} else if strings.IndexByte(vals[0], ';') > 0 {
			vals = strings.Split(vals[0], ";")
		}
	}
	ch.feed(vals, trust)
}

// label should not be empty
func (ch *canaryHeader) intoHeader(header http.Header) {
	header.Set(headerXCanary, ch.String())
}

func (ch *canaryHeader) feed(vals []string, trust bool) {
	for i, v := range vals {
		v = strings.TrimSpace(v)
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
		case v == "nofallback":
			ch.nofallback = true
		case v == "testing":
			ch.testing = true
		default:
			if i == 0 && validLabelReg.MatchString(v) {
				ch.label = v
			}
		}
	}
	if ch.testing && ch.label == "" {
		ch.label = "testing"
	}
}

// label should not be empty
func (ch *canaryHeader) String() string {
	if ch.label == "" {
		return ""
	}
	vals := make([]string, 0, 4)
	vals = append(vals, fmt.Sprintf("label=%s", ch.label))
	if ch.product != "" {
		vals = append(vals, fmt.Sprintf("product=%s", ch.product))
	}
	if ch.uid != "" {
		vals = append(vals, fmt.Sprintf("uid=%s", ch.uid))
	}
	if ch.client != "" {
		vals = append(vals, fmt.Sprintf("client=%s", ch.client))
	}
	if ch.channel != "" {
		vals = append(vals, fmt.Sprintf("channel=%s", ch.channel))
	}
	if ch.app != "" {
		vals = append(vals, fmt.Sprintf("app=%s", ch.app))
	}
	if ch.version != "" {
		vals = append(vals, fmt.Sprintf("version=%s", ch.version))
	}
	if ch.nofallback {
		vals = append(vals, "nofallback")
	}
	if ch.testing {
		vals = append(vals, "testing")
	}
	return strings.Join(vals, ",")
}

func convertSameSite(sameSite string) http.SameSite {
	switch sameSite {
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	default:
		return 0
	}
}

func anonymousID(feeds ...string) string {
	h := sha1.New()
	for _, v := range feeds {
		io.WriteString(h, v)
	}
	return fmt.Sprintf("anon-%x", h.Sum(nil))
}

func strSliceHas(s []string, t string) bool {
	for _, v := range s {
		if v == t {
			return true
		}
	}
	return false
}
