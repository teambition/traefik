package canary

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/log"
)

var storesMu sync.Mutex
var stores = make(map[string]*Store)

// LabelStore ...
type LabelStore struct {
	s               *Store
	logger          log.Logger
	expiration      time.Duration
	mustFetchLabels func(ctx context.Context, uid, requestID string) (labels []Label, timestamp int64)
}

// Store ...
type Store struct {
	mu                 sync.RWMutex
	maxCacheSize       int
	cacheCleanDuration time.Duration
	shouldRound        time.Time
	liveMap            map[string]*entry
	staleMap           map[string]*entry
}

type entry struct {
	mu       sync.Mutex
	value    []Label
	expireAt time.Time
}

// Label ...
type Label struct {
	Label    string   `json:"l"`
	Clients  []string `json:"cls,omitempty"`
	Channels []string `json:"chs,omitempty"`
}

// MatchClient ...
func (l *Label) MatchClient(client string) bool {
	if len(l.Clients) == 0 {
		return true
	}
	for _, c := range l.Clients {
		if c == client {
			return true
		}
	}
	return false
}

// MatchChannel ...
func (l *Label) MatchChannel(channel string) bool {
	if len(l.Channels) == 0 {
		return true
	}
	for _, c := range l.Channels {
		if c == channel {
			return true
		}
	}
	return false
}

// NewLabelStore ...
func NewLabelStore(logger log.Logger, cfg dynamic.Canary, expiration, cacheCleanDuration time.Duration, name string) *LabelStore {
	product := cfg.Product
	apiURL := cfg.Server
	// apiURL ex. https://labelServerHost/api/labels?uid=%s&product=%s
	if !strings.Contains(apiURL, "%s") { // append default API path.
		if apiURL[len(apiURL)-1] == '/' {
			apiURL = apiURL[:len(apiURL)-1]
		}
		apiURL += "/users/%s/labels:cache?product=%s"
	}

	storesMu.Lock()
	// LabelStores share Store with same apiURL, but always update Store'config to latest
	s, ok := stores[name]
	if !ok {
		s = &Store{
			maxCacheSize:       cfg.MaxCacheSize,
			cacheCleanDuration: cacheCleanDuration,
			shouldRound:        time.Now().UTC().Add(cacheCleanDuration),
			liveMap:            make(map[string]*entry),
			staleMap:           make(map[string]*entry),
		}
		stores[name] = s
	} else {
		s.updateConfig(cfg.MaxCacheSize, cacheCleanDuration)
	}
	storesMu.Unlock()

	ls := &LabelStore{logger: logger, s: s, expiration: expiration}
	ls.mustFetchLabels = func(ctx context.Context, uid, requestID string) ([]Label, int64) {
		url := fmt.Sprintf(apiURL, uid, product)
		return MustGetUserLabels(ctx, url, requestID, logger)
	}
	return ls
}

// MustLoadLabels ...
func (ls *LabelStore) MustLoadLabels(ctx context.Context, uid, requestID string) []Label {
	now := time.Now().UTC()
	e, round := ls.s.mustLoadEntry(uid, now)
	if round {
		ls.logger.Infof("Round cache: current stale cache %d, live cache %d, trigger %s",
			len(ls.s.staleMap), len(ls.s.liveMap), uid)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	fetchLabels := false

	if e.value == nil || e.expireAt.Before(now) {
		labels, ts := ls.mustFetchLabels(ctx, uid, requestID)
		e.value = labels
		e.expireAt = time.Unix(ts, 0).Add(ls.expiration)
		fetchLabels = true
	}

	if span := opentracing.SpanFromContext(ctx); span != nil {
		span.SetTag("fetched-labels", fetchLabels)
	}

	return e.value
}

// updateConfig ...
func (s *Store) updateConfig(maxCacheSize int, cacheCleanDuration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxCacheSize = maxCacheSize
	s.cacheCleanDuration = cacheCleanDuration
}

func (s *Store) mustLoadEntry(key string, now time.Time) (*entry, bool) {
	s.mu.RLock()
	e, ok := s.liveMap[key]
	round := len(s.liveMap) > s.maxCacheSize || s.shouldRound.Before(now)
	s.mu.RUnlock()

	if ok && !round {
		return e, round
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok = s.liveMap[key]
	if !ok {
		if e, ok = s.staleMap[key]; ok && e != nil {
			s.liveMap[key] = e // move entry from staleMap to liveMap
			s.staleMap[key] = nil
		}
	}

	if !ok || e == nil {
		e = &entry{}
		s.liveMap[key] = e
	}

	round = len(s.liveMap) > s.maxCacheSize || s.shouldRound.Before(now) // check again
	if round {
		s.shouldRound = now.Add(s.cacheCleanDuration)
		// make a round: drop staleMap and create new liveMap
		s.staleMap = s.liveMap
		s.liveMap = make(map[string]*entry, len(s.staleMap)/2)
	}
	return e, round
}
