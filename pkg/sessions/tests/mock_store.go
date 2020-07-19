package tests

import (
	"context"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
)

// Store is a generic in-memory implementation of persistence.Store
// for mocking in tests
type Store struct {
	cache *cache.Cache
}

// NewStore creates a Store
func NewStore() *Store {
	return &Store{
		cache: cache.New(168*time.Hour, 168*time.Hour),
	}
}

// Save sets a key to the data to the memory cache
func (s *Store) Save(_ context.Context, key string, value []byte, exp time.Duration) error {
	s.cache.Set(key, value, exp)
	return nil
}

// Load gets data from the memory cache via a key
func (s *Store) Load(_ context.Context, key string) ([]byte, error) {
	data, found := s.cache.Get(key)
	if !found {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return data.([]byte), nil
}

// Clear deletes an entry from the memory cache
func (s *Store) Clear(_ context.Context, key string) error {
	s.cache.Delete(key)
	return nil
}
