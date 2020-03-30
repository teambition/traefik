package lrr

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLRRBalancer(t *testing.T) {
	t.Run("removeNsPort should work", func(t *testing.T) {
		a := assert.New(t)
		a.Equal("core", removeNsPort("core", "core"))
		a.Equal("core-beta", removeNsPort("core-beta", "core"))
		a.Equal("core-beta", removeNsPort("ng-core-beta", "core"))
		a.Equal("core-beta", removeNsPort("ng-beta-core-beta", "core"))
		a.Equal("core-beta", removeNsPort("ng-beta-core-beta-80", "core"))
		a.Equal("core-beta", removeNsPort("ng-beta-core-beta-8080", "core"))
		a.Equal("core-dev", removeNsPort("ng-beta-core-dev-8080", "core"))
		a.Equal("core-dev", removeNsPort("core-dev-8080", "urbs-core"))
		a.Equal("urbs-core-dev", removeNsPort("ng-dev-urbs-core-dev-8080", "urbs-core"))
	})

	t.Run("sliceHandler should work", func(t *testing.T) {
		a := assert.New(t)
		handler := http.NotFoundHandler()

		// b := New("urbs-api", handler)
		s := make(sliceHandler, 0)
		s = s.AppendAndSort(&namedHandler{name: "lrr-api", Handler: handler})
		s = s.AppendAndSort(&namedHandler{name: "lrr-api-stable", Handler: handler})
		a.Equal("lrr-api-stable", s[0].name)
		a.Equal("lrr-api", s[1].name)

		s = s.AppendAndSort(&namedHandler{name: "lrr-api-canary", Handler: handler})
		a.Equal("lrr-api-stable", s[0].name)
		a.Equal("lrr-api-canary", s[1].name)
		a.Equal("lrr-api", s[2].name)

		s = s.AppendAndSort(&namedHandler{name: "lrr", Handler: handler})
		a.Equal("lrr-api-stable", s[0].name)
		a.Equal("lrr-api-canary", s[1].name)
		a.Equal("lrr-api", s[2].name)
		a.Equal("lrr", s[3].name)

		s = s.AppendAndSort(&namedHandler{name: "lrr-api-canary-v1", Handler: handler})
		a.Equal("lrr-api-canary-v1", s[0].name)
		a.Equal("lrr-api-stable", s[1].name)
		a.Equal("lrr-api-canary", s[2].name)
		a.Equal("lrr-api", s[3].name)
		a.Equal("lrr", s[4].name)

		s = s.AppendAndSort(&namedHandler{name: "lrr-api-canary-v2", Handler: handler})
		a.Equal("lrr-api-canary-v1", s[0].name)
		a.Equal("lrr-api-canary-v2", s[1].name)
		a.Equal("lrr-api-stable", s[2].name)
		a.Equal("lrr-api-canary", s[3].name)
		a.Equal("lrr-api", s[4].name)
		a.Equal("lrr", s[5].name)

		type ir struct {
			i string
			r string
		}
		list := []ir{
			ir{"lrr", "lrr"},
			ir{"lrr-api", "lrr-api"},
			ir{"lrr-api-stable", "lrr-api-stable"},
			ir{"lrr-api-canary", "lrr-api-canary"},
			ir{"lrr-api-canary-v2", "lrr-api-canary-v2"},
			ir{"lrr-api-canary-v1", "lrr-api-canary-v1"},
			ir{"lrr-api-canary-v3", "lrr-api-canary"},
			ir{"lrr-api-canary-v1-beta1", "lrr-api-canary-v1"},
			ir{"lrr-api-dev", "lrr-api"},
			ir{"lrr-web", "lrr"},
		}

		for _, ele := range list {
			h := s.Match(ele.i)
			a.Equal(ele.r, h.name)
		}

		h := s.Match("api")
		a.Nil(h)

		h = s.Match("lr")
		a.Nil(h)
	})
}
