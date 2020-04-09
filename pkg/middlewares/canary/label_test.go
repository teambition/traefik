package canary

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLabelStruct(t *testing.T) {
	t.Run("matchClient and matchChannel should work", func(t *testing.T) {
		a := assert.New(t)

		l := Label{}
		a.True(l.MatchClient(""))
		a.True(l.MatchClient("any"))

		a.True(l.MatchChannel(""))
		a.True(l.MatchChannel("any"))

		l = Label{Clients: []string{"web"}, Channels: []string{"stable"}}
		a.False(l.MatchClient(""))
		a.True(l.MatchClient("web"))
		a.False(l.MatchClient("any"))

		a.False(l.MatchChannel(""))
		a.True(l.MatchChannel("stable"))
		a.False(l.MatchChannel("any"))
	})
}

func TestLabelStore(t *testing.T) {
	t.Run("mustLoadEntry should work", func(t *testing.T) {
		a := assert.New(t)

		cfg := dynamic.Canary{MaxCacheSize: 3, Server: "localhost", Product: "T"}
		ls := NewLabelStore(logrus.StandardLogger(), cfg, time.Second, time.Second*2)
		ls.mustFetchLabels = func(ctx context.Context, uid, requestID string) ([]Label, int64) {
			return []Label{{Label: requestID}}, time.Now().Unix()
		}

		u1 := ls.mustLoadEntry("u1", time.Now())
		var wg sync.WaitGroup

		wg.Add(3)
		go func(e *entry) {
			defer wg.Done()
			a.Equal(e, ls.mustLoadEntry("u1", time.Now()))
		}(u1)

		go func(e *entry) {
			defer wg.Done()
			a.Equal(e, ls.mustLoadEntry("u1", time.Now()))
		}(u1)

		go func(e *entry) {
			defer wg.Done()
			ls.mustLoadEntry("u2", time.Now())
			ls.mustLoadEntry("u3", time.Now())
			ls.mustLoadEntry("u4", time.Now())
			// Round cache
			a.Equal(0, len(ls.liveMap))
			a.Equal(e, ls.mustLoadEntry("u1", time.Now()))
		}(u1)

		wg.Wait()
	})

	t.Run("MustLoadLabels should work", func(t *testing.T) {
		a := assert.New(t)

		cfg := dynamic.Canary{MaxCacheSize: 3, Server: "localhost", Product: "T"}
		ls := NewLabelStore(logrus.StandardLogger(), cfg, time.Second, time.Second*2)
		ls.mustFetchLabels = func(ctx context.Context, uid, requestID string) ([]Label, int64) {
			return []Label{{Label: requestID}}, time.Now().Unix()
		}

		labels := ls.MustLoadLabels(context.Background(), "u1", "v1")
		a.Equal(1, len(labels))
		a.Equal("v1", labels[0].Label)

		// cache value
		labels = ls.MustLoadLabels(context.Background(), "u1", "v2")
		a.Equal(1, len(labels))
		a.Equal("v1", labels[0].Label)

		// cache expired
		time.Sleep(time.Millisecond * 1100)
		// cache value
		labels = ls.MustLoadLabels(context.Background(), "u1", "v2")
		a.Equal(1, len(labels))
		a.Equal("v2", labels[0].Label)

		labels = ls.MustLoadLabels(context.Background(), "u1", "v3")
		a.Equal(1, len(labels))
		a.Equal("v2", labels[0].Label)

		_ = ls.MustLoadLabels(context.Background(), "u2", "v2")
		_ = ls.MustLoadLabels(context.Background(), "u3", "v2")
		_ = ls.MustLoadLabels(context.Background(), "u4", "v2")

		// Round cache
		a.Equal(0, len(ls.liveMap))

		// load cache from staleMap
		labels = ls.MustLoadLabels(context.Background(), "u1", "v4")
		a.Equal("v2", labels[0].Label)
		labels = ls.MustLoadLabels(context.Background(), "u2", "v4")
		a.Equal("v2", labels[0].Label)

		var call int32
		ls.mustFetchLabels = func(ctx context.Context, uid, requestID string) ([]Label, int64) {
			atomic.AddInt32(&call, 1)
			return []Label{{Label: requestID}}, time.Now().Unix()
		}

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			time.Sleep(time.Millisecond * 1100)
			_ = ls.MustLoadLabels(context.Background(), "u1", "v4")
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Millisecond * 1100)
			_ = ls.MustLoadLabels(context.Background(), "u1", "v5")
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Millisecond * 1100)
			_ = ls.MustLoadLabels(context.Background(), "u1", "v6")
		}()
		wg.Wait()
		a.Equal(int32(1), call)
	})
}
