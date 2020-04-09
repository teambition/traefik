package canary

import (
	"sync"
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

		var wg sync.WaitGroup
		wg.Add(10)
		for i := 0; i < 10; i++ {
			go func() {
				defer wg.Done()
				hc.CountFailure()
			}()
		}
		wg.Wait()
		a.False(hc.MaybeHealthy())

		time.Sleep(time.Millisecond * 1010)
		a.True(hc.MaybeHealthy())
		hc.CountFailure()
		a.False(hc.MaybeHealthy())

		hc.Reset()
		a.True(hc.MaybeHealthy())
		a.Nil(hc.timer)
	})
}
