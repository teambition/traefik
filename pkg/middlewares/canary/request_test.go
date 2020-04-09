package canary

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHealthcheck(t *testing.T) {
	t.Run("should work", func(t *testing.T) {
		a := assert.New(t)

		hc := &healthcheck{
			failuresThreshold: 3,
			retry:             time.Second,
		}

		a.True(hc.MaybeHealthy())
		hc.CountFailure()
		a.True(hc.MaybeHealthy())
		for i := 0; i < 10; i++ {
			go func() {
				hc.CountFailure()
			}()
		}
		a.False(hc.MaybeHealthy())

		time.Sleep(time.Millisecond * 1001)
		a.True(hc.MaybeHealthy())
		hc.CountFailure()
		a.False(hc.MaybeHealthy())

		hc.Reset()
		a.True(hc.MaybeHealthy())
		a.Nil(hc.timer)
	})
}
