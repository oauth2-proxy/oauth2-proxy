package tests

import (
	"context"
	"fmt"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// entry is a MockStore cache entry with an expiration
type entry struct {
	data       []byte
	expiration time.Duration
}

// MockStore is a generic in-memory implementation of persistence.Store
// for mocking in tests
type MockStore struct {
	cache              map[string]entry
	lockCache          map[string]*MockLock
	userSessionMapping map[string]string
	elapsed            time.Duration
}

// NewMockStore creates a MockStore
func NewMockStore() *MockStore {
	return &MockStore{
		cache:              map[string]entry{},
		userSessionMapping: map[string]string{},
		lockCache:          map[string]*MockLock{},
		elapsed:            0 * time.Second,
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

// SaveAndEvict sets a key to the data to the memory cache, maps the user string to this key and deletes any previous
// key the user string mapped to
func (s *MockStore) SaveAndEvict(_ context.Context, key string, value []byte, user string, exp time.Duration) error {
	s.cache[key] = entry{
		data:       value,
		expiration: exp,
	}
	if old, ok := s.userSessionMapping[user]; ok {
		delete(s.cache, old)
	}
	s.userSessionMapping[user] = key
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

func (s *MockStore) Lock(key string) sessions.Lock {
	if s.lockCache[key] != nil {
		return s.lockCache[key]
	}
	lock := &MockLock{}
	s.lockCache[key] = lock
	return lock
}

func (s *MockStore) VerifyConnection(_ context.Context) error {
	return nil
}

// FastForward simulates the flow of time to test expirations
func (s *MockStore) FastForward(duration time.Duration) {
	for _, mockLock := range s.lockCache {
		mockLock.FastForward(duration)
	}
	s.elapsed += duration
}
