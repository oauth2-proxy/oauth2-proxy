package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

const (
	defaultTimeout = 30 * time.Second
)

// Store implements the persistence.Store interface using HTTP REST API
type Store struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
}

// NewStore creates a new HTTP-based session store
func NewStore(baseURL, apiKey string) (*Store, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("http store base URL cannot be empty")
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	return &Store{
		baseURL: u,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}, nil
}

// Save stores the session data with the given key and TTL
func (s *Store) Save(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	// Encode data as base64 for JSON transport
	encodedData := base64.StdEncoding.EncodeToString(data)

	reqBody := map[string]interface{}{
		"data":        encodedData,
		"ttl_seconds": int64(ttl.Seconds()),
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	reqURL := s.buildURL("/sessions/" + url.PathEscape(key))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	s.setHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Load retrieves the session data for the given key
func (s *Store) Load(ctx context.Context, key string) ([]byte, error) {
	reqURL := s.buildURL("/sessions/" + url.PathEscape(key))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	s.setHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("session not found")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	var respBody struct {
		Data string `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Decode base64 data
	data, err := base64.StdEncoding.DecodeString(respBody.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %w", err)
	}

	return data, nil
}

// Clear removes the session data for the given key
func (s *Store) Clear(ctx context.Context, key string) error {
	reqURL := s.buildURL("/sessions/" + url.PathEscape(key))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	s.setHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Accept both 200 and 404 as success for delete operations
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Lock returns a no-op lock implementation.
// Distributed locking is not supported by the HTTP store as it would require
// additional endpoints on the storage backend.
func (s *Store) Lock(_ string) sessions.Lock {
	return &sessions.NoOpLock{}
}

// VerifyConnection checks if the HTTP store is accessible
func (s *Store) VerifyConnection(ctx context.Context) error {
	reqURL := s.buildURL("/health")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	s.setHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health check failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// buildURL constructs a full URL from the base URL and path
func (s *Store) buildURL(urlPath string) string {
	u := *s.baseURL
	u.Path = path.Join(u.Path, urlPath)
	return u.String()
}

// setHeaders sets the required headers for the request
func (s *Store) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
}
