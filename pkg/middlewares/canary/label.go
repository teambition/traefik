package canary

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/log"
)

// LabelStore ...
type LabelStore struct {
	logger             log.Logger
	mu                 sync.RWMutex
	expiration         time.Duration
	cacheCleanDuration time.Duration
	shouldRound        time.Time
	maxCacheSize       int
	liveMap            map[string]*entry
	staleMap           map[string]*entry
	mustFetchLabels    func(ctx context.Context, uid, requestID string) (labels []Label, timestamp int64)
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
func NewLabelStore(logger log.Logger, cfg dynamic.Canary, expiration, cacheCleanDuration time.Duration) *LabelStore {
	ls := &LabelStore{
		logger:             logger,
		maxCacheSize:       cfg.MaxCacheSize,
		expiration:         expiration,
		cacheCleanDuration: cacheCleanDuration,
		shouldRound:        time.Now().UTC().Add(cacheCleanDuration),
		liveMap:            make(map[string]*entry),
		staleMap:           make(map[string]*entry),
	}

	product := cfg.Product
	apiURL := cfg.Server
	// apiURL ex. https://labelServerHost/api/labels?uid=%s&product=%s
	if !strings.Contains(apiURL, "%s") { // append default API path.
		if apiURL[len(apiURL)-1] == '/' {
			apiURL = apiURL[:len(apiURL)-1]
		}
		apiURL += "/users/%s/labels:cache?product=%s"
	}

	ls.mustFetchLabels = func(ctx context.Context, uid, requestID string) ([]Label, int64) {
		url := fmt.Sprintf(apiURL, uid, product)
		return MustGetUserLabels(ctx, url, requestID, logger)
	}
	return ls
}

// MustLoadLabels ...
func (s *LabelStore) MustLoadLabels(ctx context.Context, uid, requestID string) []Label {
	now := time.Now().UTC()
	e := s.mustLoadEntry(uid, now)

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.value == nil || e.expireAt.Before(now) {
		labels, ts := s.mustFetchLabels(ctx, uid, requestID)
		e.value = labels
		e.expireAt = time.Unix(ts, 0).Add(s.expiration)
	}

	return e.value
}

func (s *LabelStore) mustLoadEntry(key string, now time.Time) *entry {
	s.mu.RLock()
	e, ok := s.liveMap[key]
	shouldRound := len(s.liveMap) > s.maxCacheSize || s.shouldRound.Before(now)
	s.mu.RUnlock()

	if ok && !shouldRound {
		return e
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

	if len(s.liveMap) > s.maxCacheSize || s.shouldRound.Before(now) {
		s.logger.Infof("Round cache, stale cache size: %d, live cache size: %d, trigger: %s, shouldRound: %s",
			len(s.staleMap), len(s.liveMap), key, s.shouldRound.Format(time.RFC3339))
		s.shouldRound = now.Add(s.cacheCleanDuration)
		// make a round: drop staleMap and create new liveMap
		s.staleMap = s.liveMap
		s.liveMap = make(map[string]*entry, len(s.staleMap)/2)
	}
	return e
}
