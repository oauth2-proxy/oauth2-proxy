package providers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func newAppleServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func generateTestECPrivateKey() (*ecdsa.PrivateKey, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	return privateKey, pem.EncodeToMemory(pemBlock), nil
}

func newAppleProvider() (*AppleProvider, *ecdsa.PrivateKey, error) {
	privKey, privKeyPEM, err := generateTestECPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	p, err := NewAppleProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        "",
			ClientID:     "com.example.client",
		},
		options.AppleOptions{
			TeamID:     "TEAM123456",
			KeyID:      "KEY1234567",
			PrivateKey: string(privKeyPEM),
		},
		options.OIDCOptions{},
	)
	if err != nil {
		return nil, nil, err
	}

	return p, privKey, nil
}

func TestNewAppleProvider(t *testing.T) {
	g := NewWithT(t)

	_, privKeyPEM, err := generateTestECPrivateKey()
	g.Expect(err).ToNot(HaveOccurred())

	// Test that defaults are set when calling for a new provider
	provider, err := NewAppleProvider(
		&ProviderData{
			ClientID: "com.example.client",
		},
		options.AppleOptions{
			TeamID:     "TEAM123456",
			KeyID:      "KEY1234567",
			PrivateKey: string(privKeyPEM),
		},
		options.OIDCOptions{},
	)
	g.Expect(err).ToNot(HaveOccurred())

	providerData := provider.Data()
	g.Expect(providerData.ProviderName).To(Equal("Apple"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://appleid.apple.com/auth/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://appleid.apple.com/auth/token"))
	g.Expect(providerData.Scope).To(Equal("openid email name"))
}

func TestAppleProviderMissingTeamID(t *testing.T) {
	_, privKeyPEM, err := generateTestECPrivateKey()
	assert.NoError(t, err)

	_, err = NewAppleProvider(
		&ProviderData{},
		options.AppleOptions{
			KeyID:      "KEY1234567",
			PrivateKey: string(privKeyPEM),
		},
		options.OIDCOptions{},
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "teamID")
}

func TestAppleProviderMissingKeyID(t *testing.T) {
	_, privKeyPEM, err := generateTestECPrivateKey()
	assert.NoError(t, err)

	_, err = NewAppleProvider(
		&ProviderData{},
		options.AppleOptions{
			TeamID:     "TEAM123456",
			PrivateKey: string(privKeyPEM),
		},
		options.OIDCOptions{},
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "keyID")
}

func TestAppleProviderMissingPrivateKey(t *testing.T) {
	_, err := NewAppleProvider(
		&ProviderData{},
		options.AppleOptions{
			TeamID: "TEAM123456",
			KeyID:  "KEY1234567",
		},
		options.OIDCOptions{},
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key")
}

func TestAppleProviderBothPrivateKeyOptions(t *testing.T) {
	_, privKeyPEM, err := generateTestECPrivateKey()
	assert.NoError(t, err)

	_, err = NewAppleProvider(
		&ProviderData{},
		options.AppleOptions{
			TeamID:         "TEAM123456",
			KeyID:          "KEY1234567",
			PrivateKey:     string(privKeyPEM),
			PrivateKeyFile: "/path/to/key.p8",
		},
		options.OIDCOptions{},
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set both")
}

func TestAppleProviderGenerateClientSecret(t *testing.T) {
	p, privKey, err := newAppleProvider()
	assert.NoError(t, err)
	assert.NotNil(t, p)

	secret, err := p.generateClientSecret()
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Verify the JWT
	token, err := jwt.Parse(secret, func(token *jwt.Token) (interface{}, error) {
		return &privKey.PublicKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	// Verify claims
	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, "TEAM123456", claims["iss"])
	assert.Equal(t, "com.example.client", claims["sub"])

	// Verify header
	assert.Equal(t, "ES256", token.Method.Alg())
	assert.Equal(t, "KEY1234567", token.Header["kid"])
}

func TestAppleProviderGetLoginURL(t *testing.T) {
	p, _, err := newAppleProvider()
	assert.NoError(t, err)

	result := p.GetLoginURL("https://example.com/callback", "state123", "nonce123", url.Values{})
	assert.Contains(t, result, "response_mode=form_post")
	assert.Contains(t, result, "state=state123")
	assert.Contains(t, result, "redirect_uri=")
}

func TestAppleProviderRedeem(t *testing.T) {
	p, _, err := newAppleProvider()
	assert.NoError(t, err)
	assert.NotNil(t, p)

	// Create a mock ID token
	expiresIn := int64(3600)
	idTokenClaims := jwt.MapClaims{
		"iss":   "https://appleid.apple.com",
		"sub":   "user123",
		"aud":   "com.example.client",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": "user@example.com",
	}

	// Sign with test key for mock purposes
	privKey, _, _ := generateTestECPrivateKey()
	idToken := jwt.NewWithClaims(jwt.SigningMethodES256, idTokenClaims)
	signedIDToken, err := idToken.SignedString(privKey)
	assert.NoError(t, err)

	// Set up mock server response
	body, err := json.Marshal(map[string]interface{}{
		"access_token":  "mock_access_token",
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"refresh_token": "mock_refresh_token",
		"id_token":      signedIDToken,
	})
	assert.NoError(t, err)

	var server *httptest.Server
	p.RedeemURL, server = newAppleServer(body)
	defer server.Close()

	session, err := p.Redeem(context.Background(), "https://example.com/callback", "code123", "")
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "mock_access_token", session.AccessToken)
	assert.Equal(t, "mock_refresh_token", session.RefreshToken)
	assert.Equal(t, signedIDToken, session.IDToken)
}

func TestAppleProviderRefreshSession(t *testing.T) {
	p, _, err := newAppleProvider()
	assert.NoError(t, err)
	assert.NotNil(t, p)

	expiresIn := int64(3600)

	// Set up mock server response
	body, err := json.Marshal(map[string]interface{}{
		"access_token":  "new_access_token",
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"refresh_token": "new_refresh_token",
	})
	assert.NoError(t, err)

	var server *httptest.Server
	p.RedeemURL, server = newAppleServer(body)
	defer server.Close()

	session := &sessions.SessionState{
		RefreshToken: "old_refresh_token",
	}

	refreshed, err := p.RefreshSession(context.Background(), session)
	assert.NoError(t, err)
	assert.True(t, refreshed)
	assert.Equal(t, "new_access_token", session.AccessToken)
	assert.Equal(t, "new_refresh_token", session.RefreshToken)
}
