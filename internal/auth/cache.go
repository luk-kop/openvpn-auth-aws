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
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return IdentityResult{}, false
	}
	if time.Since(entry.result.CheckedAt) > c.ttl {
		c.mu.Lock()
		// Re-check under write lock — another goroutine may have refreshed it.
		if e, ok := c.entries[key]; ok && time.Since(e.result.CheckedAt) > c.ttl {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return IdentityResult{}, false
	}
	return entry.result, true
}

func (c *ReauthCache) Put(key string, result IdentityResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{result: result}
}
