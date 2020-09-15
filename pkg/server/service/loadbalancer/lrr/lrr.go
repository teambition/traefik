package lrr

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

type namedHandler struct {
	http.Handler
	name string
}

// New creates a new load balancer.
func New(defaultServiceName string, handler http.Handler) *Balancer {
	return &Balancer{serviceName: defaultServiceName, defaultHandler: handler}
}

type sliceHandler []*namedHandler

func (s sliceHandler) Match(name string, fallback bool) *namedHandler {
	for _, handler := range s {
		if name == handler.name {
			return handler
		} else if fallback && strings.HasPrefix(name, handler.name) {
			return handler
		}
	}
	return nil
}

func (s sliceHandler) AppendAndSort(h *namedHandler) sliceHandler {
	s = append(s, h)
	sort.SliceStable(s, func(i, j int) bool {
		return len(s[i].name) > len(s[j].name)
	})
	return s
}

// Balancer is a labeled load-balancer of services, which select service by label.
type Balancer struct {
	serviceName    string
	defaultHandler http.Handler
	handlers       sliceHandler
}

func (b *Balancer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	label, fallback := extractLabel(req.Header)
	name := b.serviceName
	if label != "" {
		name = fmt.Sprintf("%s-%s", name, label)
		if handler := b.handlers.Match(name, fallback); handler != nil {
			handler.ServeHTTP(w, req)
			return
		}
	}

	if b.defaultHandler != nil && (fallback || label == "") {
		b.defaultHandler.ServeHTTP(w, req)
		return
	}

	http.Error(w, http.StatusText(http.StatusInternalServerError)+": no service found in LRR Balancer", http.StatusInternalServerError)
}

// AddService adds a handler.
// It is not thread safe with ServeHTTP.
func (b *Balancer) AddService(fullServiceName string, handler http.Handler) {
	h := &namedHandler{Handler: handler, name: removeNsPort(fullServiceName, b.serviceName)}
	b.handlers = b.handlers.AppendAndSort(h)
}

var isPortReg = regexp.MustCompile(`^\d+$`)

// full service name format (build by fullServiceName function): namespace-serviceName-port
func removeNsPort(fullServiceName, ServiceName string) string {
	i := strings.Index(fullServiceName, ServiceName)
	if i > 0 {
		fullServiceName = fullServiceName[i:] // remove namespace
	}
	return strings.TrimRight(fullServiceName, "0123456789-") // remove port
}

func extractLabel(header http.Header) (string, bool) {
	// standard specification, reference to https://www.w3.org/TR/trace-context/#tracestate-header
	// X-Canary: label=beta,product=urbs,uid=5c4057f0be825b390667abee,nofallback ...
	// and compatible with
	// X-Canary: beta
	// X-Canary: label=beta; product=urbs; uid=5c4057f0be825b390667abee; nofallback ...
	label := ""
	fallback := true
	vals := header.Values("X-Canary")
	if len(vals) == 1 {
		if strings.IndexByte(vals[0], ',') > 0 {
			vals = strings.Split(vals[0], ",")
		} else if strings.IndexByte(vals[0], ';') > 0 {
			vals = strings.Split(vals[0], ";")
		}
	}
	for i, v := range vals {
		v = strings.TrimSpace(v)
		switch {
		case strings.HasPrefix(v, "label="):
			label = v[6:]
		case v == "nofallback":
			fallback = false
		case i == 0:
			label = v
		}
	}
	return label, fallback
}
