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

type entryList struct {
	data       []string
	expiration time.Duration
}

// MockStore is a generic in-memory implementation of persistence.Store
// for mocking in tests
type MockStore struct {
	cache     map[string]entry
	cacheList map[string]entryList
	lockCache map[string]*MockLock
	elapsed   time.Duration
}

// LoadList implements persistence.Store.
func (s *MockStore) LoadList(ctx context.Context, key string) ([]string, error) {
	entry, ok := s.cacheList[key]
	if !ok || entry.expiration <= s.elapsed {
		delete(s.cache, key)
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return entry.data, nil
}

// RPush implements persistence.Store.
func (s *MockStore) RPush(ctx context.Context, key string, value string, time time.Duration) error {
	entry, ok := s.cacheList[key]
	if ok {
		// If the key exists, check if the expiration is still valid
		entry.data = append(entry.data, value)
		s.cacheList[key] = entry
	} else {
		// If the key does not exist, create a new entryList
		if s.cacheList == nil {
			s.cacheList = make(map[string]entryList)
		}
		s.cacheList[key] = entryList{
			data:       []string{value},
			expiration: time,
		}
	}
	return nil
}

// NewMockStore creates a MockStore
func NewMockStore() *MockStore {
	return &MockStore{
		cache:     map[string]entry{},
		lockCache: map[string]*MockLock{},
		elapsed:   0 * time.Second,
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
