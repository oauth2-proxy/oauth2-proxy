package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHTTPStore_SaveLoadClear tests the basic Save, Load, and Clear operations
func TestHTTPStore_SaveLoadClear(t *testing.T) {
	// Create a mock HTTP server
	sessions := make(map[string]map[string]interface{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check API key
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodPut:
			// Save session
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			key := r.URL.Path[len("/sessions/"):]
			sessions[key] = req
			w.WriteHeader(http.StatusOK)

		case http.MethodGet:
			// Load session
			key := r.URL.Path[len("/sessions/"):]
			if session, exists := sessions[key]; exists {
				resp := map[string]string{
					"data": session["data"].(string),
				}
				json.NewEncoder(w).Encode(resp)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}

		case http.MethodDelete:
			// Clear session
			key := r.URL.Path[len("/sessions/"):]
			delete(sessions, key)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	// Create HTTP store
	store, err := NewStore(server.URL, "test-api-key")
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	ctx := context.Background()
	key := "test-session-key"
	data := []byte("test session data")
	ttl := 1 * time.Hour

	// Test Save
	if err := store.Save(ctx, key, data, ttl); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Test Load
	loadedData, err := store.Load(ctx, key)
	if err != nil {
		t.Fatalf("Failed to load session: %v", err)
	}

	if string(loadedData) != string(data) {
		t.Fatalf("Loaded data does not match saved data: got %s, want %s", string(loadedData), string(data))
	}

	// Test Clear
	if err := store.Clear(ctx, key); err != nil {
		t.Fatalf("Failed to clear session: %v", err)
	}

	// Verify session is cleared
	_, err = store.Load(ctx, key)
	if err == nil {
		t.Fatalf("Expected error when loading cleared session, got nil")
	}
}

// TestHTTPStore_VerifyConnection tests the health check functionality
func TestHTTPStore_VerifyConnection(t *testing.T) {
	// Create a mock HTTP server with health endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create HTTP store
	store, err := NewStore(server.URL, "test-api-key")
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Test VerifyConnection
	ctx := context.Background()
	if err := store.VerifyConnection(ctx); err != nil {
		t.Fatalf("Failed to verify connection: %v", err)
	}
}

// TestHTTPStore_InvalidURL tests that invalid URLs are rejected
func TestHTTPStore_InvalidURL(t *testing.T) {
	_, err := NewStore("ht!tp://invalid url with spaces", "test-api-key")
	if err == nil {
		t.Fatalf("Expected error for invalid URL, got nil")
	}
}

// TestHTTPStore_EmptyURL tests that empty URLs are rejected
func TestHTTPStore_EmptyURL(t *testing.T) {
	_, err := NewStore("", "test-api-key")
	if err == nil {
		t.Fatalf("Expected error for empty URL, got nil")
	}
}

// TestHTTPStore_Base64Encoding tests that data is properly base64 encoded
func TestHTTPStore_Base64Encoding(t *testing.T) {
	var capturedData string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var req map[string]interface{}
			json.NewDecoder(r.Body).Decode(&req)
			capturedData = req["data"].(string)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	store, _ := NewStore(server.URL, "")
	ctx := context.Background()
	testData := []byte("test data with special chars: \x00\x01\x02")

	store.Save(ctx, "test-key", testData, 1*time.Hour)

	// Verify the data was base64 encoded
	decodedData, err := base64.StdEncoding.DecodeString(capturedData)
	if err != nil {
		t.Fatalf("Failed to decode captured data: %v", err)
	}

	if string(decodedData) != string(testData) {
		t.Fatalf("Decoded data does not match original: got %v, want %v", decodedData, testData)
	}
}
