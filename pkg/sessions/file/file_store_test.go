package file

import (
	"encoding/json"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"io/ioutil"
	"os"
	"sync"
	"testing"
)

func TestNewFileSessionStore(t *testing.T) {
	t.Run("creates new store with empty file", func(t *testing.T) {
		tmpFile, _ := ioutil.TempFile("", "test_sessions.json")
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		store, err := NewFileSessionStore(tmpFile.Name())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(store.sessions) != 0 {
			t.Fatalf("expected sessions to be empty, got %d", len(store.sessions))
		}
	})

	t.Run("returns error for invalid file", func(t *testing.T) {
		store, err := NewFileSessionStore("invalid/path")
		if store != nil || err == nil {
			t.Fatalf("expected error, but got none")
		}
	})
}

func TestSessionStore_Save(t *testing.T) {
	t.Run("saves new session", func(t *testing.T) {
		tmpFile, _ := ioutil.TempFile("", "test_sessions.json")
		defer os.Remove(tmpFile.Name())
		store, _ := NewFileSessionStore(tmpFile.Name())
		state := &sessions.SessionState{Email: "test@example.com"}

		err := store.Save("key", state)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		data, _ := ioutil.ReadFile(tmpFile.Name())
		savedSessions := map[string]*sessions.SessionState{}
		json.Unmarshal(data, &savedSessions)

		if savedState, exists := savedSessions["key"]; !exists || savedState.Email != state.Email {
			t.Fatalf("session was not saved correctly")
		}
	})

	t.Run("handles marshal error", func(t *testing.T) {
		store := &SessionStore{
			sessions: map[string]*sessions.SessionState{"key": nil},
		}
		err := store.Save("key", nil)
		if err == nil {
			t.Fatalf("expected error, but got none")
		}
	})
}

func TestSessionStore_Load(t *testing.T) {
	t.Run("loads existing session", func(t *testing.T) {
		store := &SessionStore{
			sessions: map[string]*sessions.SessionState{"key": {Email: "test@example.com"}},
			lock:     sync.Mutex{},
		}
		state, err := store.Load("key")
		if err != nil || state.Email != "test@example.com" {
			t.Fatalf("failed to load existing session")
		}
	})

	t.Run("returns error if session not found", func(t *testing.T) {
		store := &SessionStore{sessions: map[string]*sessions.SessionState{}, lock: sync.Mutex{}}
		_, err := store.Load("key")
		if err == nil {
			t.Fatalf("expected error, but got none")
		}
	})
}

func TestSessionStore_Clear(t *testing.T) {
	t.Run("clears existing session", func(t *testing.T) {
		tmpFile, _ := ioutil.TempFile("", "test_sessions.json")
		defer os.Remove(tmpFile.Name())
		store := &SessionStore{
			filePath: tmpFile.Name(),
			sessions: map[string]*sessions.SessionState{"key": {Email: "test@example.com"}},
		}

		err := store.Clear("key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, exists := store.sessions["key"]; exists {
			t.Fatalf("failed to clear session")
		}
	})

	t.Run("handles clearing non-existing session", func(t *testing.T) {
		store := &SessionStore{sessions: map[string]*sessions.SessionState{}}
		err := store.Clear("key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestSessionStore_loadSessionsFromFile(t *testing.T) {
	t.Run("loads sessions from an existing file", func(t *testing.T) {
		tmpFile, _ := ioutil.TempFile("", "test_sessions.json")
		defer os.Remove(tmpFile.Name())

		sessions := map[string]*sessions.SessionState{"key": {Email: "test@example.com"}}
		data, _ := json.Marshal(sessions)
		_ = ioutil.WriteFile(tmpFile.Name(), data, 0600)

		store := &SessionStore{filePath: tmpFile.Name()}
		err := store.loadSessionsFromFile()
		if err != nil || len(store.sessions) != 1 || store.sessions["key"].Email != "test@example.com" {
			t.Fatalf("failed to load sessions from file")
		}
	})

	t.Run("initializes empty store if file does not exist", func(t *testing.T) {
		store := &SessionStore{filePath: "non_existing_file.json"}
		err := store.loadSessionsFromFile()
		if err != nil || len(store.sessions) != 0 {
			t.Fatalf("expected empty sessions, got error or non-empty sessions")
		}
	})
}

func TestSessionStore_saveSessionsToFile(t *testing.T) {
	t.Run("saves sessions to file", func(t *testing.T) {
		tmpFile, _ := ioutil.TempFile("", "test_sessions.json")
		defer os.Remove(tmpFile.Name())

		store := &SessionStore{
			filePath: tmpFile.Name(),
			sessions: map[string]*sessions.SessionState{"key": {Email: "test@example.com"}},
		}

		err := store.saveSessionsToFile()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		data, _ := ioutil.ReadFile(tmpFile.Name())
		savedSessions := map[string]*sessions.SessionState{}
		json.Unmarshal(data, &savedSessions)

		if savedState, exists := savedSessions["key"]; !exists || savedState.Email != "test@example.com" {
			t.Fatalf("session was not saved correctly")
		}
	})

	t.Run("handles file write errors gracefully", func(t *testing.T) {
		store := &SessionStore{filePath: "/invalid_path/file.json"}
		err := store.saveSessionsToFile()
		if err == nil {
			t.Fatalf("expected error, but got none")
		}
	})
}
