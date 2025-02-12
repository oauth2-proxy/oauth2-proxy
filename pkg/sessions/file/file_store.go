package file

import (
	"encoding/json"
	"errors"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"io/ioutil"
	"os"
	"sync"
)

const (
	DefaultFilePermissions = 0600
)

type SessionStore struct {
	filePath string
	lock     sync.Mutex
	sessions map[string]*sessions.SessionState
}

// NewFileSessionStore creates a new session store with file persistence.
func NewFileSessionStore(filePath string) (sessions.SessionStore, error) {
	store := &SessionStore{
		filePath: filePath,
		sessions: make(map[string]*sessions.SessionState),
	}
	if err := store.loadSessionsFromFile(); err != nil {
		return nil, err
	}
	return store, nil
}

// Save persists a session state for a given key.
func (store *SessionStore) Save(key string, sessionState *sessions.SessionState) error {
	return store.withLock(func() error {
		store.sessions[key] = sessionState
		return store.saveSessionsToFile()
	})
}

// Load retrieves a session by key.
func (store *SessionStore) Load(key string) (*sessions.SessionState, error) {
	var session *sessions.SessionState
	err := store.withLock(func() error {
		var exists bool
		session, exists = store.sessions[key]
		if !exists {
			return errors.New("session not found")
		}
		return nil
	})
	return session, err
}

// Clear removes a session by key.
func (store *SessionStore) Clear(key string) error {
	return store.withLock(func() error {
		delete(store.sessions, key)
		return store.saveSessionsToFile()
	})
}

// loadSessionsFromFile loads all sessions from the JSON file.
func (store *SessionStore) loadSessionsFromFile() error {
	if _, err := os.Stat(store.filePath); os.IsNotExist(err) {
		store.sessions = make(map[string]*sessions.SessionState)
		return nil
	}

	data, err := ioutil.ReadFile(store.filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &store.sessions)
}

// saveSessionsToFile writes all sessions to the JSON file with proper formatting.
func (store *SessionStore) saveSessionsToFile() error {
	data, err := json.MarshalIndent(store.sessions, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(store.filePath, data, DefaultFilePermissions)
}

// withLock handles locking and running critical sections.
func (store *SessionStore) withLock(action func() error) error {
	store.lock.Lock()
	defer store.lock.Unlock()
	return action()
}
