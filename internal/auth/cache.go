package auth

import (
	"sync"
	"time"
)

type cacheEntry struct {
	result IdentityResult
}

type ReauthCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

func NewReauthCache(ttl time.Duration) *ReauthCache {
	return &ReauthCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

func (c *ReauthCache) Get(key string) (IdentityResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok {
		return IdentityResult{}, false
	}
	if time.Since(entry.result.CheckedAt) > c.ttl {
		return IdentityResult{}, false
	}
	return entry.result, true
}

func (c *ReauthCache) Put(key string, result IdentityResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{result: result}
}
