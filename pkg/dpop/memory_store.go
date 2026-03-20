package dpop

import (
	"context"
	"sync"
	"time"
)

type memoryStoreEntry struct {
	expiresAt time.Time
}

// MemoryDpopStore is an in-memory implementation of the DpopStore interface.
// It is intended for testing and single-instance deployments.
type MemoryDpopStore struct {
	mu          sync.Mutex
	entries     map[string]memoryStoreEntry
	lastCleanup time.Time
	dirty       bool
}

// NewMemoryDpopStore creates a new in-memory DpopStore.
func NewMemoryDpopStore() *MemoryDpopStore {
	return &MemoryDpopStore{
		entries:     make(map[string]memoryStoreEntry),
		lastCleanup: time.Now(),
	}
}

// MarkJtiSeen checks if a JTI scoped by JKT has been seen. If not, it stores it with the
// specified absolute expiration time. Returns true if it was newly added.
func (c *MemoryDpopStore) MarkJtiSeen(ctx context.Context, jkt string, jti string, expiresAt time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := jkt + ":" + jti
	now := time.Now()

	// Preemptive cleanup
	if c.dirty && now.Sub(c.lastCleanup) > 1*time.Minute {
		c.cleanUpLocked(now)
	}

	if entry, exists := c.entries[key]; exists {
		if now.Before(entry.expiresAt) {
			return false, nil // Already seen and not expired
		}
		// It exists but has expired. We can overwrite it and treat it as unseen.
	}

	// Not seen or expired, add it
	c.entries[key] = memoryStoreEntry{
		expiresAt: expiresAt,
	}
	c.dirty = true

	return true, nil
}

// CleanUp removes expired entries from the store.
// Call this periodically if running for long periods.
func (c *MemoryDpopStore) CleanUp() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cleanUpLocked(time.Now())
}

func (c *MemoryDpopStore) cleanUpLocked(now time.Time) {
	for k, v := range c.entries {
		if now.After(v.expiresAt) {
			delete(c.entries, k)
		}
	}
	c.lastCleanup = now
	c.dirty = false
}
