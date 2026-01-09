package memory

import (
	"context"
	"errors"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"sync"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// InMemoryStore is an in-memory implementation of the Store interface.
type InMemoryStore struct {
	mu       sync.RWMutex
	store    map[string][]byte
	timeouts map[string]time.Time
}

// NewInMemoryStore creates a new instance of InMemoryStore.
func NewInMemoryStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	ims := &InMemoryStore{
		store:    make(map[string][]byte),
		timeouts: make(map[string]time.Time),
	}
	
	return persistence.NewManager(ims, cookieOpts), nil
}

// Save stores the session data in memory with a specified expiration time.
func (s *InMemoryStore) Save(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.store[key] = value
	s.timeouts[key] = time.Now().Add(expiration)
	return nil
}

// Load retrieves the session data from memory.
func (s *InMemoryStore) Load(ctx context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if timeout, ok := s.timeouts[key]; ok {
		if time.Now().After(timeout) {
			delete(s.store, key)
			delete(s.timeouts, key)
			return nil, errors.New("session expired")
		}
	}

	value, ok := s.store[key]
	if !ok {
		return nil, errors.New("session not found")
	}
	return value, nil
}

// Clear removes the session data from memory.
func (s *InMemoryStore) Clear(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.store, key)
	delete(s.timeouts, key)
	return nil
}

// Lock returns a lock for the given key.
func (s *InMemoryStore) Lock(key string) sessions.Lock {
	return &inMemoryLock{key: key, store: s}
}

// VerifyConnection is a no-op for in-memory storage.
func (s *InMemoryStore) VerifyConnection(ctx context.Context) error {
	return nil
}

// inMemoryLock is a simple implementation of the sessions.Lock interface.
type inMemoryLock struct {
	key   string
	store *InMemoryStore
}

// Obtain tries to create a lock or returns an error if one already exists.
func (l *inMemoryLock) Obtain(ctx context.Context, expiration time.Duration) error {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	// Logic to add a lock with a timeout
	return nil
}

// Peek checks if the lock exists.
func (l *inMemoryLock) Peek(ctx context.Context) (bool, error) {
	l.store.mu.RLock()
	defer l.store.mu.RUnlock()
	// Logic to check if the lock exists
	return true, nil
}

// Refresh updates the expiration timeout of an existing lock.
func (l *inMemoryLock) Refresh(ctx context.Context, expiration time.Duration) error {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	// Logic to update the lock timeout
	return nil
}

// Release removes the existing lock.
func (l *inMemoryLock) Release(ctx context.Context) error {
	l.store.mu.Unlock()
	return nil
}
