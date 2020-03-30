package lrr

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const labelKey = "X-Canary"

var isPortReg = regexp.MustCompile(`^\d+$`)

type namedHandler struct {
	http.Handler
	name string
}

// New creates a new load balancer.
func New(defaultServiceName string, handler http.Handler) *Balancer {
	return &Balancer{serviceName: defaultServiceName, defaultHandler: handler}
}

type sliceHandler []*namedHandler

func (s sliceHandler) Match(name string) *namedHandler {
	for _, handler := range s {
		if strings.HasPrefix(name, handler.name) {
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
	// X-Canary: beta
	// X-Canary: label=beta; product=urbs; uid=5c4057f0be825b390667abee; ...
	label := req.Header.Get(labelKey)
	if label != "" && strings.HasPrefix(label, "label=") {
		label = label[6:]
	}

	name := b.serviceName
	if label != "" {
		name = fmt.Sprintf("%s-%s", name, label)
		if handler := b.handlers.Match(name); handler != nil {
			handler.ServeHTTP(w, req)
			return
		}
	}

	if b.defaultHandler != nil {
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

// full service name format (build by fullServiceName function): namespace-serviceName-port
func removeNsPort(fullServiceName, ServiceName string) string {
	i := strings.Index(fullServiceName, ServiceName)
	if i > 0 {
		fullServiceName = fullServiceName[i:] // remove namespace
	}
	return strings.TrimRight(fullServiceName, "0123456789-") // remove port
}
