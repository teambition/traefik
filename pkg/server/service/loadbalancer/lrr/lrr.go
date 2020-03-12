package lrr

import (
	"fmt"
	"net/http"
	"regexp"
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

// Balancer is a labeled load-balancer of services, which select service by label.
type Balancer struct {
	serviceName    string
	defaultHandler http.Handler
	handlers       []*namedHandler
}

func (b *Balancer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// X-Canary: beta
	// X-Canary: label=beta; uid=5c4057f0be825b390667abee; ...
	label := req.Header.Get(labelKey)
	if label != "" && strings.HasPrefix(label, "label=") {
		label = label[6:]
	}

	name := b.serviceName
	if label != "" {
		name = fmt.Sprintf("%s-%s", name, label)
		for _, handler := range b.handlers {
			if handler.name == name {
				handler.ServeHTTP(w, req)
				return
			}
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
	b.handlers = append(b.handlers, h)
}

// full service name format (build by fullServiceName function): namespace-serviceName-port
func removeNsPort(fullServiceName, ServiceName string) string {
	i := strings.Index(fullServiceName, ServiceName)
	if i > 0 {
		fullServiceName = fullServiceName[i:] // remove namespace
	}
	return strings.TrimRight(fullServiceName, "0123456789-") // remove port
}
