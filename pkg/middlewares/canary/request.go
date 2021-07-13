package canary

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/version"
)

func init() {
	userAgent = fmt.Sprintf("Go/%v Traefik/%s (Canary Middleware)", runtime.Version(), version.Version)
}

var userAgent string

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 15 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       25 * time.Second,
	TLSHandshakeTimeout:   3 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 5 * time.Second,
}

var client = &http.Client{
	Transport: tr,
	Timeout:   time.Second,
}

var hc = &healthcheck{
	failuresThreshold: 5,
	retry:             time.Second * 10,
}

type healthcheck struct {
	failures          uint64
	failuresThreshold uint64
	retry             time.Duration
	timer             *time.Timer
}

func (h *healthcheck) CountFailure() uint64 {
	i := atomic.AddUint64(&h.failures, 1)
	if i == h.failuresThreshold {
		h.timer = time.AfterFunc(h.retry, func() {
			// make MaybeHealthy() returns true
			atomic.StoreUint64(&h.failures, h.failuresThreshold-1)
		})
	}
	return i
}

func (h *healthcheck) Reset() {
	if atomic.SwapUint64(&h.failures, 0) != 0 && h.timer != nil {
		h.timer.Stop()
		h.timer = nil
	}
}

func (h *healthcheck) MaybeHealthy() bool {
	return atomic.LoadUint64(&h.failures) < h.failuresThreshold
}

type labelsRes struct {
	Timestamp int64   `json:"timestamp"` // []label 构建时间，Unix seconds
	Result    []Label `json:"result"`    // 空数组也保留
}

func getUserLabels(ctx context.Context, api, xRequestID string) (*labelsRes, error) {
	if ctx.Err() != nil {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", api, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set(headerUA, userAgent)
	req.Header.Set(headerXRequestID, xRequestID)
	if span := opentracing.SpanFromContext(ctx); span != nil {
		opentracing.GlobalTracer().Inject(
			span.Context(),
			opentracing.HTTPHeaders,
			opentracing.HTTPHeadersCarrier(req.Header))
	}

	resp, err := client.Do(req)
	if err != nil {
		if err.(*url.Error).Unwrap() == context.Canceled {
			return nil, nil
		}

		c := hc.CountFailure()
		return nil, fmt.Errorf("xRequestId: %s, failures: %d, request error: %v", xRequestID, c, err)
	}

	hc.Reset()

	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || err != nil || len(respBody) == 0 {
		return nil, fmt.Errorf("xRequestId: %s, getUserLabels error: %d, %d, %v, %s",
			xRequestID, resp.StatusCode, resp.ContentLength, err, string(respBody))
	}

	res := &labelsRes{}
	if err = json.Unmarshal(respBody, res); err != nil {
		return nil, fmt.Errorf("xRequestId: %s, getUserLabels Unmarshal error: %v, %s",
			xRequestID, err, string(respBody))
	}
	return res, nil
}

// MustGetUserLabels returns labels and timestamp
func MustGetUserLabels(ctx context.Context, api, xRequestID string, logger log.Logger) ([]Label, int64) {
	ts := time.Now().UTC().Unix()
	rs := []Label{}

	if hc.MaybeHealthy() {
		if res, err := getUserLabels(ctx, api, xRequestID); err != nil {
			logger.Error(err)
		} else if res != nil {
			rs = res.Result
			if res.Timestamp > 0 && res.Timestamp < ts {
				ts = res.Timestamp
			}
		}
	}

	return rs, ts
}
