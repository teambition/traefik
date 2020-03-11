package canary

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/log"
)

type labelStore struct {
	product            string
	server             string
	logger             log.Logger
	mu                 sync.Mutex
	expiration         time.Duration
	cacheCleanDuration time.Duration
	maxCacheSize       int
	shouldRound        time.Time
	liveMap            map[string]*entry
	staleMap           map[string]*entry
}

type entry struct {
	mu       sync.Mutex
	value    []label
	expireAt time.Time
}

type label struct {
	Label    string `json:"l"`
	Clients  string `json:"cls,omitempty"`
	Channels string `json:"chs,omitempty"`
}

func newLabelStore(cfg dynamic.Canary, logger log.Logger, expiration time.Duration, cacheCleanDuration time.Duration) *labelStore {
	return &labelStore{
		expiration:         expiration,
		logger:             logger,
		product:            cfg.Product,
		server:             cfg.Server,
		maxCacheSize:       cfg.MaxCacheSize,
		cacheCleanDuration: cacheCleanDuration,
		shouldRound:        time.Now().UTC().Add(cacheCleanDuration),
		liveMap:            make(map[string]*entry),
		staleMap:           make(map[string]*entry),
	}
}

func (s *labelStore) mustLoad(ctx context.Context, uid string, header http.Header) []label {
	now := time.Now().UTC()
	e := s.mustLoadEntity(uid, now)

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.value == nil || e.expireAt.Before(now) {
		res := s.fetch(ctx, uid, header)
		e.value = res.Result
		e.expireAt = time.Unix(res.Timestamp, 0).UTC().Add(s.expiration)
	}

	return e.value
}

func (s *labelStore) mustLoadEntity(key string, now time.Time) *entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.liveMap[key]
	if !ok {
		if e, ok = s.staleMap[key]; ok && e != nil {
			s.liveMap[key] = e // move entity from staleMap to liveMap
			s.staleMap[key] = nil
		}
	}

	if len(s.liveMap) > s.maxCacheSize || s.shouldRound.Before(now) {
		s.logger.Infof("Round cache, stale cache size: %d, live cache size: %d", len(s.staleMap), len(s.liveMap))
		s.shouldRound = now.Add(s.cacheCleanDuration)
		// make a round: drop staleMap and create new liveMap
		s.staleMap = s.liveMap
		s.liveMap = make(map[string]*entry, len(s.staleMap)/2)
	}

	if !ok {
		e = &entry{}
		s.liveMap[key] = e
	}
	return e
}

func (s *labelStore) fetch(ctx context.Context, uid string, header http.Header) *labelsRes {
	url := fmt.Sprintf("%s/users/%s/labels:cache?product=%s", s.server, uid, s.product)
	res, err := getUserLabels(ctx, url, header.Get("X-Request-ID"))
	now := time.Now().UTC().Unix()
	if err != nil {
		res = &labelsRes{Result: []label{}, Timestamp: now}
		s.logger.Error(err)
	} else if res.Timestamp > now {
		res.Timestamp = now
	}
	return res
}
