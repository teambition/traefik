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

const roundDuration = time.Minute * 10

type labelStore struct {
	product     string
	server      string
	logger      log.Logger
	mu          sync.Mutex
	expire      time.Duration
	shouldRound time.Time
	liveMap     map[string]*entity
	staleMap    map[string]*entity
}

type entity struct {
	mu       sync.Mutex
	value    []label
	expireAt time.Time
}

type label struct {
	Label    string `json:"l"`
	Clients  string `json:"cls,omitempty"`
	Channels string `json:"chs,omitempty"`
}

func newLabelStore(cfg dynamic.Canary, logger log.Logger, expire time.Duration) *labelStore {
	return &labelStore{
		product:     cfg.Product,
		server:      cfg.Server,
		expire:      expire,
		logger:      logger,
		shouldRound: time.Now().UTC().Add(roundDuration),
		liveMap:     make(map[string]*entity),
		staleMap:    make(map[string]*entity),
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
		e.expireAt = time.Unix(res.Timestamp, 0).UTC().Add(s.expire)
	}

	return e.value
}

func (s *labelStore) mustLoadEntity(key string, now time.Time) *entity {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.liveMap[key]
	if !ok {
		if e, ok = s.staleMap[key]; ok {
			s.liveMap[key] = e // move entity from staleMap to liveMap
			delete(s.staleMap, key)
		}
	}
	if !ok {
		e = &entity{}
		s.liveMap[key] = e
	}

	if s.shouldRound.Before(now) {
		s.shouldRound = now.Add(roundDuration)
		// make a round: drop staleMap and create new liveMap
		s.staleMap = s.liveMap
		s.liveMap = make(map[string]*entity)
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
