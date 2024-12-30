package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func createIntrospectClaims() string {
	claims := map[string]interface{}{
		"sub": "1234567890",
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(claimsBytes)
}

func Test_PicsSignOutAllSessionsReturnsErrorWhenUserIDIsNotFound(t *testing.T) {
	_, err := PicsSignOutAllSessions("http://localhost:8080/test", "", "")

	assert.Error(t, err)
}

func Test_getUserID(t *testing.T) {
	introspectClaims := createIntrospectClaims()
	userID, err := getUserID(introspectClaims)

	assert.NoError(t, err)
	assert.Equal(t, "1234567890", userID)
}

func Test_PicsSignOutAllSessionsReturns200Ok(t *testing.T) {
	introspectClaims := createIntrospectClaims()
	accessToken := "validAccessToken"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer "+accessToken, r.Header.Get("Authorization"))
		assert.Equal(t, "1", r.Header.Get("API-Version"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	resp, err := PicsSignOutAllSessions(server.URL+"/{user_id}", introspectClaims, accessToken)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode())
}
