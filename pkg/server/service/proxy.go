package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/types"
)

// StatusClientClosedRequest non-standard HTTP status code for client disconnection
const StatusClientClosedRequest = 499

// StatusClientClosedRequestText non-standard HTTP status for client disconnection
const StatusClientClosedRequestText = "Client Closed Request"

func buildProxy(passHostHeader *bool, responseForwarding *dynamic.ResponseForwarding, defaultRoundTripper http.RoundTripper, bufferPool httputil.BufferPool, responseModifier func(*http.Response) error) (http.Handler, error) {
	var flushInterval types.Duration
	if responseForwarding != nil {
		err := flushInterval.Set(responseForwarding.FlushInterval)
		if err != nil {
			return nil, fmt.Errorf("error creating flush interval: %v", err)
		}
	}
	if flushInterval == 0 {
		flushInterval = types.Duration(100 * time.Millisecond)
	}

	proxy := &httputil.ReverseProxy{
		Director: func(outReq *http.Request) {
			u := outReq.URL
			if outReq.RequestURI != "" {
				parsedURL, err := url.ParseRequestURI(outReq.RequestURI)
				if err == nil {
					u = parsedURL
				}
			}

			outReq.URL.Path = u.Path
			outReq.URL.RawPath = u.RawPath
			outReq.URL.RawQuery = u.RawQuery
			outReq.RequestURI = "" // Outgoing request should not have RequestURI

			outReq.Proto = "HTTP/1.1"
			outReq.ProtoMajor = 1
			outReq.ProtoMinor = 1

			if _, ok := outReq.Header["User-Agent"]; !ok {
				outReq.Header.Set("User-Agent", "")
			}

			// Do not pass client Host header unless optsetter PassHostHeader is set.
			if passHostHeader != nil && !*passHostHeader {
				outReq.Host = outReq.URL.Host
			}

			// Even if the websocket RFC says that headers should be case-insensitive,
			// some servers need Sec-WebSocket-Key, Sec-WebSocket-Extensions, Sec-WebSocket-Accept,
			// Sec-WebSocket-Protocol and Sec-WebSocket-Version to be case-sensitive.
			// https://tools.ietf.org/html/rfc6455#page-20
			outReq.Header["Sec-WebSocket-Key"] = outReq.Header["Sec-Websocket-Key"]
			outReq.Header["Sec-WebSocket-Extensions"] = outReq.Header["Sec-Websocket-Extensions"]
			outReq.Header["Sec-WebSocket-Accept"] = outReq.Header["Sec-Websocket-Accept"]
			outReq.Header["Sec-WebSocket-Protocol"] = outReq.Header["Sec-Websocket-Protocol"]
			outReq.Header["Sec-WebSocket-Version"] = outReq.Header["Sec-Websocket-Version"]
			delete(outReq.Header, "Sec-Websocket-Key")
			delete(outReq.Header, "Sec-Websocket-Extensions")
			delete(outReq.Header, "Sec-Websocket-Accept")
			delete(outReq.Header, "Sec-Websocket-Protocol")
			delete(outReq.Header, "Sec-Websocket-Version")
		},
		Transport:      defaultRoundTripper,
		FlushInterval:  time.Duration(flushInterval),
		ModifyResponse: responseModifier,
		BufferPool:     bufferPool,
		ErrorHandler: func(w http.ResponseWriter, request *http.Request, err error) {
			statusCode := http.StatusInternalServerError

			switch {
			case err == io.EOF:
				statusCode = http.StatusBadGateway
			case err == context.Canceled:
				statusCode = StatusClientClosedRequest
			default:
				if e, ok := err.(net.Error); ok {
					if e.Timeout() {
						statusCode = http.StatusGatewayTimeout
					} else {
						statusCode = http.StatusBadGateway
					}
				}
			}

			if statusCode > 500 {
				log.Warnf("Error proxying: %d, xRequestID: %s, host: %s, url: %s, caused by: %v",
					statusCode, request.Header.Get("X-Request-ID"), request.Host, request.URL.String(), err)
			}
			w.WriteHeader(statusCode)
			_, werr := w.Write([]byte(statusText(statusCode)))
			if werr != nil {
				log.Warnf("Error while writing status code: %s", werr.Error())
			}
		},
	}

	return proxy, nil
}

func statusText(statusCode int) string {
	if statusCode == StatusClientClosedRequest {
		return StatusClientClosedRequestText
	}
	return http.StatusText(statusCode)
}
