package api

import (
	"github.com/bitly/go-simplejson"
	"github.com/bmizerany/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testBackend(response_code int, payload string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(response_code)
			w.Write([]byte(payload))
		}))
}

func TestRequest(t *testing.T) {
	backend := testBackend(200, "{\"foo\": \"bar\"}")
	defer backend.Close()

	req, _ := http.NewRequest("GET", backend.URL, nil)
	response, err := Request(req)
	assert.Equal(t, nil, err)
	result, err := response.Get("foo").String()
	assert.Equal(t, nil, err)
	assert.Equal(t, "bar", result)
}

func TestRequestFailure(t *testing.T) {
	// Create a backend to generate a test URL, then close it to cause a
	// connection error.
	backend := testBackend(200, "{\"foo\": \"bar\"}")
	backend.Close()

	req, err := http.NewRequest("GET", backend.URL, nil)
	assert.Equal(t, nil, err)
	resp, err := Request(req)
	assert.Equal(t, (*simplejson.Json)(nil), resp)
	assert.NotEqual(t, nil, err)
	if !strings.HasSuffix(err.Error(), "connection refused") {
		t.Error("expected error when a connection fails")
	}
}

func TestHttpErrorCode(t *testing.T) {
	backend := testBackend(404, "{\"foo\": \"bar\"}")
	defer backend.Close()

	req, err := http.NewRequest("GET", backend.URL, nil)
	assert.Equal(t, nil, err)
	resp, err := Request(req)
	assert.Equal(t, (*simplejson.Json)(nil), resp)
	assert.NotEqual(t, nil, err)
}

func TestJsonParsingError(t *testing.T) {
	backend := testBackend(200, "not well-formed JSON")
	defer backend.Close()

	req, err := http.NewRequest("GET", backend.URL, nil)
	assert.Equal(t, nil, err)
	resp, err := Request(req)
	assert.Equal(t, (*simplejson.Json)(nil), resp)
	assert.NotEqual(t, nil, err)
}
