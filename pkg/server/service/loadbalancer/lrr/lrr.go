package lrr

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const labelKey = "X-Canary-Label"

var isDigitsReg = regexp.MustCompile(`^\d+$`)

type namedHandler struct {
	http.Handler
	name string
}

// New creates a new load balancer.
func New(defaultServiceName string, handler http.Handler) *Balancer {
	return &Balancer{serviceName: removeNsPort(defaultServiceName), defaultHandler: handler}
}

// Balancer is a labeled load-balancer of services, which select service by label.
type Balancer struct {
	serviceName    string
	defaultHandler http.Handler
	handlers       []*namedHandler
}

func (b *Balancer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	label := req.Header.Get(labelKey)
	name := b.serviceName

	if label == "" {
		if cookie, _ := req.Cookie(labelKey); cookie != nil {
			label = cookie.Value
		}
	}

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
func (b *Balancer) AddService(name string, handler http.Handler) {
	h := &namedHandler{Handler: handler, name: removeNsPort(name)}
	b.handlers = append(b.handlers, h)
}

// full service name format (build by fullServiceName function): namespace-serviceName-port
func removeNsPort(fullServiceName string) string {
	strs := strings.Split(fullServiceName, "-")
	if len(strs) > 1 {
		strs = strs[1:] // remove namespace
	}
	if len(strs) > 1 && isDigitsReg.MatchString(strs[len(strs)-1]) {
		strs = strs[:len(strs)-1] // remove port
	}
	return strings.Join(strs, "-")
}
