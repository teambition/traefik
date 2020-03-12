package lrr

import (
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
}
