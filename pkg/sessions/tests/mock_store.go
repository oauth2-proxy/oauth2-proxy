package tests

import (
	"context"
	"fmt"
	"time"
)

// entry is a MockStore cache entry with an expiration
type entry struct {
	data       []byte
	expiration time.Duration
}

// MockStore is a generic in-memory implementation of persistence.Store
// for mocking in tests
type MockStore struct {
	cache   map[string]entry
	elapsed time.Duration
}

// NewMockStore creates a MockStore
func NewMockStore() *MockStore {
	return &MockStore{
		cache:   map[string]entry{},
		elapsed: 0 * time.Second,
	}
}

// Save sets a key to the data to the memory cache
func (s *MockStore) Save(_ context.Context, key string, value []byte, exp time.Duration) error {
	s.cache[key] = entry{
		data:       value,
		expiration: exp,
	}
	return nil
}

// Load gets data from the memory cache via a key
func (s *MockStore) Load(_ context.Context, key string) ([]byte, error) {
	entry, ok := s.cache[key]
	if !ok || entry.expiration <= s.elapsed {
		delete(s.cache, key)
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return entry.data, nil
}

// Clear deletes an entry from the memory cache
func (s *MockStore) Clear(_ context.Context, key string) error {
	delete(s.cache, key)
	return nil
}

// FastForward simulates the flow of time to test expirations
func (s *MockStore) FastForward(duration time.Duration) {
	s.elapsed += duration
}
