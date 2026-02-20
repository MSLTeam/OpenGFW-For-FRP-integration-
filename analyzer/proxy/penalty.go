package proxy

import (
	"net"
	"sync"
	"time"
)

type sourcePenaltyCache struct {
	mu sync.RWMutex

	enabled      bool
	ttl          time.Duration
	triggerScore int
	blockScore   int
	maxEntries   int
	entries      map[string]time.Time
}

func newSourcePenaltyCache(cfg FeatureConfig) *sourcePenaltyCache {
	c := &sourcePenaltyCache{
		entries: make(map[string]time.Time),
	}
	c.Configure(cfg)
	return c
}

func (c *sourcePenaltyCache) Configure(cfg FeatureConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.enabled = cfg.SourcePenaltyEnabled
	c.ttl = time.Duration(cfg.SourcePenaltyTTLSeconds) * time.Second
	c.triggerScore = cfg.SourcePenaltyTriggerScore
	c.blockScore = cfg.SourcePenaltyBlockScore
	c.maxEntries = cfg.SourcePenaltyMaxEntries

	if !c.enabled {
		c.entries = make(map[string]time.Time)
		return
	}
	c.cleanupLocked(time.Now())
	if len(c.entries) > c.maxEntries {
		c.entries = make(map[string]time.Time)
	}
}

func (c *sourcePenaltyCache) MaybePenalize(ip net.IP, score int) {
	if ip == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled || score < c.triggerScore {
		return
	}
	now := time.Now()
	c.cleanupLocked(now)
	if len(c.entries) >= c.maxEntries {
		c.entries = make(map[string]time.Time)
	}
	c.entries[ip.String()] = now.Add(c.ttl)
}

func (c *sourcePenaltyCache) IsBlocked(ip net.IP) (blocked bool, ttlSec int, blockScore int) {
	if ip == nil {
		return false, 0, 0
	}
	key := ip.String()

	c.mu.RLock()
	enabled := c.enabled
	expiry, ok := c.entries[key]
	blockScore = c.blockScore
	c.mu.RUnlock()

	if !enabled || !ok {
		return false, 0, blockScore
	}
	now := time.Now()
	if !expiry.After(now) {
		c.mu.Lock()
		if exp2, ok2 := c.entries[key]; ok2 && !exp2.After(now) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return false, 0, blockScore
	}
	ttlSec = int(expiry.Sub(now).Seconds())
	if ttlSec < 1 {
		ttlSec = 1
	}
	return true, ttlSec, blockScore
}

func (c *sourcePenaltyCache) cleanupLocked(now time.Time) {
	for ip, expiry := range c.entries {
		if !expiry.After(now) {
			delete(c.entries, ip)
		}
	}
}
