package http

import (
	"testing"
)

// TestHTTPStore_BaseURLWithPath tests that base URLs with paths are handled correctly
func TestHTTPStore_BaseURLWithPath(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		expectedURL string
	}{
		{
			name:        "Simple host only",
			baseURL:     "http://localhost:8080",
			expectedURL: "http://localhost:8080/sessions/test-key",
		},
		{
			name:        "Host with single path segment",
			baseURL:     "http://localhost:8080/api",
			expectedURL: "http://localhost:8080/api/sessions/test-key",
		},
		{
			name:        "Host with multiple path segments",
			baseURL:     "http://localhost:8080/api/v1/oauth-sessions",
			expectedURL: "http://localhost:8080/api/v1/oauth-sessions/sessions/test-key",
		},
		{
			name:        "Host with trailing slash",
			baseURL:     "http://localhost:8080/api/",
			expectedURL: "http://localhost:8080/api/sessions/test-key",
		},
		{
			name:        "HTTPS with path",
			baseURL:     "https://api.example.com/v2/sessions-api",
			expectedURL: "https://api.example.com/v2/sessions-api/sessions/test-key",
		},
		{
			name:        "Host with port and path",
			baseURL:     "http://api.example.com:9000/internal/v1",
			expectedURL: "http://api.example.com:9000/internal/v1/sessions/test-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := NewStore(tt.baseURL, "test-api-key")
			if err != nil {
				t.Fatalf("Failed to create store: %v", err)
			}

			actualURL := store.buildURL("/sessions/test-key")
			if actualURL != tt.expectedURL {
				t.Errorf("URL mismatch:\nExpected: %s\nActual:   %s", tt.expectedURL, actualURL)
			}
		})
	}
}

// TestHTTPStore_HealthCheckWithPath tests health check endpoint with base path
func TestHTTPStore_HealthCheckWithPath(t *testing.T) {
	store, err := NewStore("http://localhost:8080/api/v1", "")
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	healthURL := store.buildURL("/health")
	expectedURL := "http://localhost:8080/api/v1/health"

	if healthURL != expectedURL {
		t.Errorf("Health URL mismatch:\nExpected: %s\nActual:   %s", expectedURL, healthURL)
	}
}
