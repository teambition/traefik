package canary

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
)

const testCookie = `eyJ1aWQiOiJzb21ldWlkIiwidXNlciI6eyJfaWQiOiJzb21ldWlkIiwibmFtZSI6InRlc3RlciJ9fQ==`
const testToken = `eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiJzb21ldWlkIiwidXNlciI6eyJfaWQiOiJzb21ldWlkIiwibmFtZSI6InRlc3RlciJ9fQ.qPVxAAzpRFky08W6-0O5RZWZOeg1xO5CZkmPJZkklqQ`
const testToken2 = `eyJhbGciOiJIUzI1NiJ9.eyJpZCI6InNvbWVpZCIsInVzZXIiOnsiaWQiOiJzb21laWQiLCJuYW1lIjoidGVzdGVyIn19.hkr5mZceCWUHSOOHGbt-f1G9c_FrnATiX4ukGVArHJc`
const testToken3 = `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21ldXNlciIsInVzZXIiOnsiaWQiOiJzb21ldXNlciIsIm5hbWUiOiJ0ZXN0ZXIifX0.kzVL_dF5BU_sPnsBE-FeXqaL2bR5nnPbNpvDkRm0pOU`

func TestCanaryHeader(t *testing.T) {
	t.Run("fromHeader should work", func(t *testing.T) {
		a := assert.New(t)

		ch := &canaryHeader{}
		h := http.Header{}
		ch.fromHeader(h, false)
		a.Equal("", ch.label)

		ch = &canaryHeader{}
		h = http.Header{}
		h.Set(headerXCanary, "stable")
		ch.fromHeader(h, false)
		a.Equal("stable", ch.label)

		ch = &canaryHeader{}
		h = http.Header{}
		h.Set(headerXCanary, fmt.Sprintf("label=%s", "stable"))
		ch.fromHeader(h, false)
		a.Equal("stable", ch.label)

		ch = &canaryHeader{}
		h = http.Header{}
		h.Set(headerXCanary, ".stable")
		ch.fromHeader(h, false)
		a.Equal("", ch.label)

		ch = &canaryHeader{}
		h = http.Header{}
		h.Set(headerXCanary, fmt.Sprintf("label=%s", "label"))
		h.Add(headerXCanary, fmt.Sprintf("version=%s", "version"))
		h.Add(headerXCanary, fmt.Sprintf("app=%s", "app"))
		h.Add(headerXCanary, fmt.Sprintf("channel=%s", "channel"))
		h.Add(headerXCanary, fmt.Sprintf("client=%s", "client"))
		h.Add(headerXCanary, fmt.Sprintf("uid=%s", "uid"))
		h.Add(headerXCanary, fmt.Sprintf("product=%s", "product"))
		h.Add(headerXCanary, fmt.Sprintf("ip=%s", "ip"))
		h.Add(headerXCanary, "nofallback")
		h.Add(headerXCanary, "testing")
		ch.fromHeader(h, false)
		a.Equal("label", ch.label)
		a.Equal("", ch.product)
		a.Equal("", ch.uid)
		a.Equal("client", ch.client)
		a.Equal("channel", ch.channel)
		a.Equal("app", ch.app)
		a.Equal("version", ch.version)
		a.True(ch.nofallback)
		a.True(ch.testing)

		ch = &canaryHeader{}
		h = http.Header{}
		h.Set(headerXCanary, "label=label,version=version,app=app, channel=channel,client=client, uid=uid,product=product,ip=ip,nofallback,testing")
		ch.fromHeader(h, false)
		a.Equal("label", ch.label)
		a.Equal("", ch.product)
		a.Equal("", ch.uid)
		a.Equal("client", ch.client)
		a.Equal("channel", ch.channel)
		a.Equal("app", ch.app)
		a.Equal("version", ch.version)
		a.True(ch.nofallback)
		a.True(ch.testing)
	})

	t.Run("intoHeader should work", func(t *testing.T) {
		a := assert.New(t)

		ch := &canaryHeader{}
		h := http.Header{}
		ch.intoHeader(h)
		a.Equal("", h.Get(headerXCanary))

		ch = &canaryHeader{
			label:   "label",
			product: "product",
			uid:     "uid",
			channel: "channel",
		}
		h = http.Header{}
		ch.intoHeader(h)
		a.Equal("label=label,product=product,uid=uid,channel=channel", h.Get(headerXCanary))

		chn := &canaryHeader{}
		chn.fromHeader(h, true)
		a.Equal(*ch, *chn)

		ch = &canaryHeader{
			label:      "label",
			product:    "product",
			uid:        "uid",
			client:     "client",
			channel:    "channel",
			app:        "app",
			version:    "version",
			nofallback: true,
			testing:    true,
		}
		h = http.Header{}
		ch.intoHeader(h)
		a.Equal("label=label,product=product,uid=uid,client=client,channel=channel,app=app,version=version,nofallback,testing", h.Get(headerXCanary))

		chn = &canaryHeader{}
		chn.fromHeader(h, true)
		a.Equal(*ch, *chn)
	})
}

func TestExtractUserID(t *testing.T) {
	t.Run("fromHeader should work", func(t *testing.T) {
		a := assert.New(t)
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		uid := extractUserID(req, []string{"SESS"})
		a.Equal("", uid)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		req.AddCookie(&http.Cookie{Name: "SESS", Value: testCookie})
		uid = extractUserID(req, []string{"SESS"})
		a.Equal("someuid", uid)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		req.AddCookie(&http.Cookie{Name: "SESS", Value: ""})
		req.AddCookie(&http.Cookie{Name: "TOKEN", Value: testToken2})
		uid = extractUserID(req, []string{"SESS", "TOKEN"})
		a.Equal("someid", uid)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		req.AddCookie(&http.Cookie{Name: "SESS", Value: testCookie[5:]})
		uid = extractUserID(req, []string{"SESS"})
		a.Equal("", uid)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", testToken))
		uid = extractUserID(req, []string{})
		a.Equal("someuid", uid)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		req.Header.Set("Authorization", fmt.Sprintf("OAuth %s", testToken3))
		uid = extractUserID(req, []string{})
		a.Equal("someuser", uid)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", testToken[30:]))
		uid = extractUserID(req, []string{})
		a.Equal("", uid)
	})
}

func TestCanary(t *testing.T) {
	next := http.NotFoundHandler()

	t.Run("processRequestID should work", func(t *testing.T) {
		a := assert.New(t)

		cfg := dynamic.Canary{MaxCacheSize: 3, Server: "localhost", Product: "T", AddRequestID: true}
		c, err := New(context.Background(), next, cfg, "test")

		a.Nil(err)
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw := httptest.NewRecorder()
		c.processRequestID(rw, req)
		requestID := req.Header.Get(headerXRequestID)
		a.NotEqual("", requestID)

		c.processRequestID(rw, req)
		a.Equal(requestID, req.Header.Get(headerXRequestID))
		a.Equal(requestID, rw.Header().Get(headerXRequestID))
	})

	t.Run("processCanary should work", func(t *testing.T) {
		a := assert.New(t)

		cfg := dynamic.Canary{MaxCacheSize: 3, Server: "localhost", Product: "Urbs", AddRequestID: true}
		c, err := New(context.Background(), next, cfg, "test")
		c.ls.mustFetchLabels = func(ctx context.Context, uid, requestID string) ([]Label, int64) {
			return []Label{{Label: uid}}, time.Now().Unix()
		}
		a.Nil(err)

		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw := httptest.NewRecorder()
		c.processCanary(rw, req)
		ch := &canaryHeader{}
		ch.fromHeader(req.Header, true)
		a.Equal("", ch.label)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw = httptest.NewRecorder()
		req.Header.Set(headerXCanary, "stable")
		c.processCanary(rw, req)
		ch = &canaryHeader{}
		ch.fromHeader(req.Header, true)
		a.Equal("stable", ch.label)
		a.Equal("Urbs", ch.product)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw = httptest.NewRecorder()
		req.Header.Set(headerXCanary, "label=beta")
		c.processCanary(rw, req)
		ch = &canaryHeader{}
		ch.fromHeader(req.Header, true)
		a.Equal("beta", ch.label)
		a.Equal("Urbs", ch.product)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: headerXCanary, Value: "beta"})
		c.processCanary(rw, req)
		ch = &canaryHeader{}
		ch.fromHeader(req.Header, true)
		a.Equal("beta", ch.label)
		a.Equal("Urbs", ch.product)
		a.False(ch.nofallback)
		a.False(ch.testing)
		ch = &canaryHeader{}
		ch.fromHeader(rw.Header(), true)
		a.Equal("", ch.label)
		a.Equal("", ch.product)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: headerXCanary, Value: "beta,  nofallback,testing "})
		c.processCanary(rw, req)
		ch = &canaryHeader{}
		ch.fromHeader(req.Header, true)
		a.Equal("beta", ch.label)
		a.Equal("Urbs", ch.product)
		a.True(ch.nofallback)
		a.True(ch.testing)
		ch = &canaryHeader{}
		ch.fromHeader(rw.Header(), true)
		a.Equal("", ch.label)
		a.Equal("", ch.product)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw = httptest.NewRecorder()
		req.AddCookie(&http.Cookie{Name: headerXCanary, Value: "label=beta,nofallback,testing"})
		c.processCanary(rw, req)
		ch = &canaryHeader{}
		ch.fromHeader(req.Header, true)
		a.Equal("beta", ch.label)
		a.Equal("Urbs", ch.product)
		a.True(ch.nofallback)
		a.True(ch.testing)
		ch = &canaryHeader{}
		ch.fromHeader(rw.Header(), true)
		a.Equal("", ch.label)
		a.Equal("", ch.product)

		c.canaryResponseHeader = true

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw = httptest.NewRecorder()
		req.Header.Set(headerXCanary, "label=beta,client=iOS")
		req.AddCookie(&http.Cookie{Name: headerXCanary, Value: "stable"})
		c.processCanary(rw, req)
		ch = &canaryHeader{}
		ch.fromHeader(req.Header, true)
		a.Equal("beta", ch.label)
		a.Equal("Urbs", ch.product)
		a.Equal("iOS", ch.client)
		ch = &canaryHeader{}
		ch.fromHeader(rw.Header(), true)
		a.Equal("beta", ch.label)
		a.Equal("Urbs", ch.product)
		a.Equal("iOS", ch.client)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw = httptest.NewRecorder()
		req.Header.Set("Authorization", fmt.Sprintf("OAuth %s", testToken))
		req.Header.Set(headerXCanary, "client=iOS")
		c.processCanary(rw, req)
		ch = &canaryHeader{}
		ch.fromHeader(req.Header, true)
		a.Equal("someuid", ch.label)
		a.Equal("Urbs", ch.product)
		a.Equal("iOS", ch.client)
		a.Equal("someuid", ch.uid)
		ch = &canaryHeader{}
		ch.fromHeader(rw.Header(), true)
		a.Equal("someuid", ch.label)
		a.Equal("Urbs", ch.product)
		a.Equal("iOS", ch.client)
		a.Equal("someuid", ch.uid)
	})

	t.Run("sticky should work", func(t *testing.T) {
		a := assert.New(t)

		cfg := dynamic.Canary{MaxCacheSize: 3, Server: "localhost", Product: "Urbs", Sticky: &dynamic.Sticky{
			Cookie: &dynamic.Cookie{Name: "_urbs_"},
		}}
		c, err := New(context.Background(), next, cfg, "test")
		c.ls.mustFetchLabels = func(ctx context.Context, uid, requestID string) ([]Label, int64) {
			return []Label{{Label: uid}}, time.Now().Unix()
		}
		a.Nil(err)

		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		rw := httptest.NewRecorder()
		c.processCanary(rw, req)
		ch := &canaryHeader{}
		ch.fromHeader(req.Header, true)
		a.NotEqual("", ch.label)
		a.Equal(ch.uid, ch.label)
		a.Contains(rw.Header().Get("Set-Cookie"), "_urbs_=ey")

		uid := ch.uid
		cookies := rw.Result().Cookies()
		a.Equal(1, len(cookies))
		a.Equal("_urbs_", cookies[0].Name)

		req = httptest.NewRequest("GET", "http://example.com/foo", nil)
		req.AddCookie(cookies[0])
		rw = httptest.NewRecorder()
		c.processCanary(rw, req)
		ch = &canaryHeader{}
		ch.fromHeader(req.Header, true)
		a.Equal(uid, ch.label)
		a.Equal(ch.uid, ch.label)
	})
}
