package canary

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/containous/traefik/v2/pkg/tracing"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
)

func init() {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	userAgent = fmt.Sprintf("golang/%v hostname/%s Traefik Canary Middleware", runtime.Version(), hostname)
}

var userAgent string

var tr = &http.Transport{
	TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	ForceAttemptHTTP2: true,
}

var client = &http.Client{
	Transport: tr,
	Timeout:   time.Second,
}

type labelsRes struct {
	Timestamp int64   `json:"timestamp"` // []label 构建时间，Unix seconds
	Result    []label `json:"result"`    // 空数组也保留
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
		return nil, err
	}
	defer resp.Body.Close()

	if sp != nil {
		tracing.LogResponseCode(sp, resp.StatusCode)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("getUserLabels error: %d, %s", resp.StatusCode, string(respBody))
	}

	res := &labelsRes{}
	if err = json.Unmarshal(respBody, res); err != nil {
		return nil, fmt.Errorf("getUserLabels error: %d, %s", resp.StatusCode, string(respBody))
	}

	return res, nil
}
