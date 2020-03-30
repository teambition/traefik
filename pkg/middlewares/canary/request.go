package canary

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/tracing"
	"github.com/containous/traefik/v2/pkg/version"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
)

func init() {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	userAgent = fmt.Sprintf("Go/%v Hostname/%s Traefik/%s (Canary Middleware)", runtime.Version(), hostname, version.Version)
}

var userAgent string

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   3 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

var client = &http.Client{
	Transport: tr,
	Timeout:   time.Second * 3,
}

type labelsRes struct {
	Timestamp int64   `json:"timestamp"` // []label 构建时间，Unix seconds
	Result    []Label `json:"result"`    // 空数组也保留
}

func getUserLabels(ctx context.Context, url, xRequestID string) (*labelsRes, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	var sp opentracing.Span
	if tr, _ := tracing.FromContext(req.Context()); tr != nil {
		opParts := []string{"label"}
		span, re, finish := tr.StartSpanf(req, ext.SpanKindRPCClientEnum, "canary", opParts, "/")
		sp = span
		defer finish()

		span.SetTag(headerXRequestID, xRequestID)
		ext.HTTPUrl.Set(span, re.URL.String())
		tracing.InjectRequestHeaders(re)
		req = re
	}

	req.Header.Set(headerUA, userAgent)
	req.Header.Set(headerXRequestID, xRequestID)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xRequestId: %s, request error: %s", xRequestID, err.Error())
	}
	defer resp.Body.Close()

	if sp != nil {
		tracing.LogResponseCode(sp, resp.StatusCode)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("xRequestId: %s, getUserLabels error: %d, %s", xRequestID, resp.StatusCode, string(respBody))
	}

	res := &labelsRes{}
	if err = json.Unmarshal(respBody, res); err != nil {
		return nil, fmt.Errorf("xRequestId: %s, getUserLabels error: %d, %s", xRequestID, resp.StatusCode, string(respBody))
	}

	return res, nil
}

// MustGetUserLabels returns labels and timestamp
func MustGetUserLabels(ctx context.Context, url, xRequestID string, logger log.Logger) ([]Label, int64) {
	res, err := getUserLabels(ctx, url, xRequestID)
	now := time.Now().UTC().Unix()
	if res == nil || res.Result == nil {
		res = &labelsRes{Result: []Label{}, Timestamp: now}
		logger.Error(err)
	} else if res.Timestamp > now || res.Timestamp <= 0 {
		res.Timestamp = now
	}
	return res.Result, res.Timestamp
}
