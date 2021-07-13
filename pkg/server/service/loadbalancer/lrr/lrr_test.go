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
		a.Equal("core-beta", removeNsPort("core-core-beta-80", "core"))
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
			{"lrr", "lrr"},
			{"lrr-api", "lrr-api"},
			{"lrr-api-stable", "lrr-api-stable"},
			{"lrr-api-canary", "lrr-api-canary"},
			{"lrr-api-canary-v2", "lrr-api-canary-v2"},
			{"lrr-api-canary-v1", "lrr-api-canary-v1"},
			{"lrr-api-canary-v3", "lrr-api-canary"},
			{"lrr-api-canary-v1-beta1", "lrr-api-canary-v1"},
			{"lrr-api-dev", "lrr-api"},
			{"lrr-web", "lrr"},
		}

		for _, ele := range list {
			h := s.Match(ele.i, true)
			a.Equal(ele.r, h.name)
		}

		h := s.Match("lrr", false)
		a.NotNil(h)

		h = s.Match("lrr-api", false)
		a.NotNil(h)

		h = s.Match("lrr-api-canary-v1-beta1", false)
		a.Nil(h)

		h = s.Match("api", true)
		a.Nil(h)

		h = s.Match("lr", true)
		a.Nil(h)
	})

	t.Run("extractLabel should work", func(t *testing.T) {
		a := assert.New(t)
		header := http.Header{}
		label, fallback := extractLabel(header)
		a.Equal("", label)
		a.True(fallback)

		// X-Canary: dev
		header.Set("X-Canary", "dev")
		label, fallback = extractLabel(header)
		a.Equal("dev", label)
		a.True(fallback)

		// X-Canary: label=beta,product=urbs,uid=5c4057f0be825b390667abee,nofallback ...
		header = http.Header{}
		header.Set("X-Canary", "label=beta,product=urbs,uid=5c4057f0be825b390667abee,nofallback")
		label, fallback = extractLabel(header)
		a.Equal("beta", label)
		a.False(fallback)

		header = http.Header{}
		header.Set("X-Canary", "label=dev,product=urbs,uid=5c4057f0be825b390667abee")
		label, fallback = extractLabel(header)
		a.Equal("dev", label)
		a.True(fallback)

		header = http.Header{}
		header.Set("X-Canary", "product=urbs,uid=5c4057f0be825b390667abee,nofallback,label=dev")
		label, fallback = extractLabel(header)
		a.Equal("dev", label)
		a.False(fallback)

		// X-Canary: label=beta; product=urbs; uid=5c4057f0be825b390667abee; nofallback ...
		header = http.Header{}
		header.Set("X-Canary", "label=beta; product=urbs; uid=5c4057f0be825b390667abee; nofallback")
		label, fallback = extractLabel(header)
		a.Equal("beta", label)
		a.False(fallback)

		header = http.Header{}
		header.Add("X-Canary", "label=beta")
		header.Add("X-Canary", "product=urbs")
		header.Add("X-Canary", "uid=5c4057f0be825b390667abee")
		header.Add("X-Canary", "nofallback")
		label, fallback = extractLabel(header)
		a.Equal("beta", label)
		a.False(fallback)
	})
}
