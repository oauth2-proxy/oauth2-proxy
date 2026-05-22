package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PrefixVerifier", func() {
	var (
		privateKey *rsa.PrivateKey
		server     *httptest.Server
		issuerURL  string
	)

	BeforeEach(func() {
		var err error
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())

		// Set up a mock OIDC server that serves discovery and JWKS
		mux := http.NewServeMux()
		server = httptest.NewServer(mux)
		issuerURL = server.URL + "/realms/SOT_TENANT_A"

		// OpenID Configuration endpoint
		mux.HandleFunc("/realms/SOT_TENANT_A/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			config := map[string]interface{}{
				"issuer":                                issuerURL,
				"jwks_uri":                              server.URL + "/realms/SOT_TENANT_A/.well-known/jwks.json",
				"authorization_endpoint":                server.URL + "/realms/SOT_TENANT_A/protocol/openid-connect/auth",
				"token_endpoint":                        server.URL + "/realms/SOT_TENANT_A/protocol/openid-connect/token",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(config)
		})

		// JWKS endpoint
		mux.HandleFunc("/realms/SOT_TENANT_A/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
			n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())
			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"kid": "test-key-1",
						"use": "sig",
						"alg": "RS256",
						"n":   n,
						"e":   e,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		})
	})

	AfterEach(func() {
		if server != nil {
			server.Close()
		}
	})

	Context("extractIssuerFromJWT", func() {
		It("should extract the issuer from a valid JWT", func() {
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": "https://example.com/realms/TEST",
				"sub": "user-1",
				"aud": "my-client",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			token.Header["kid"] = "test-key-1"
			signed, err := token.SignedString(privateKey)
			Expect(err).ToNot(HaveOccurred())

			issuer, err := extractIssuerFromJWT(signed)
			Expect(err).ToNot(HaveOccurred())
			Expect(issuer).To(Equal("https://example.com/realms/TEST"))
		})

		It("should return error for invalid JWT format", func() {
			_, err := extractIssuerFromJWT("not-a-jwt")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("expected 3"))
		})

		It("should return error for JWT without issuer", func() {
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub": "user-1",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			signed, err := token.SignedString(privateKey)
			Expect(err).ToNot(HaveOccurred())

			_, err = extractIssuerFromJWT(signed)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no issuer claim"))
		})
	})

	Context("Verify", func() {
		It("should reject token whose issuer does not match prefix", func() {
			pv := NewPrefixVerifier(PrefixVerifierOptions{
				Prefix:         "https://keycloak.example.com/realms/SOT_",
				Audience:       "my-client",
				AudienceClaims: []string{"aud"},
			})

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": "https://evil.example.com/realms/SOT_HACK",
				"sub": "user-1",
				"aud": "my-client",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			token.Header["kid"] = "test-key-1"
			signed, err := token.SignedString(privateKey)
			Expect(err).ToNot(HaveOccurred())

			_, err = pv.Verify(context.Background(), signed)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("does not match prefix"))
		})

		It("should verify a valid token with matching prefix", func() {
			prefix := server.URL + "/realms/SOT_"
			pv := NewPrefixVerifier(PrefixVerifierOptions{
				Prefix:         prefix,
				Audience:       "my-client",
				AudienceClaims: []string{"aud"},
			})

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": issuerURL,
				"sub": "user-1",
				"aud": "my-client",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			token.Header["kid"] = "test-key-1"
			signed, err := token.SignedString(privateKey)
			Expect(err).ToNot(HaveOccurred())

			idToken, err := pv.Verify(context.Background(), signed)
			Expect(err).ToNot(HaveOccurred())
			Expect(idToken).ToNot(BeNil())
			Expect(idToken.Issuer).To(Equal(issuerURL))
			Expect(idToken.Subject).To(Equal("user-1"))
		})

		It("should cache verifiers for repeated calls", func() {
			prefix := server.URL + "/realms/SOT_"
			pv := NewPrefixVerifier(PrefixVerifierOptions{
				Prefix:         prefix,
				Audience:       "my-client",
				AudienceClaims: []string{"aud"},
			})

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": issuerURL,
				"sub": "user-1",
				"aud": "my-client",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			token.Header["kid"] = "test-key-1"
			signed, err := token.SignedString(privateKey)
			Expect(err).ToNot(HaveOccurred())

			// First call — triggers OIDC discovery
			_, err = pv.Verify(context.Background(), signed)
			Expect(err).ToNot(HaveOccurred())

			// Second call — should use cached verifier
			_, err = pv.Verify(context.Background(), signed)
			Expect(err).ToNot(HaveOccurred())

			// Verify cache has one entry
			pv.mu.RLock()
			Expect(pv.verifiers).To(HaveLen(1))
			Expect(pv.verifiers).To(HaveKey(issuerURL))
			pv.mu.RUnlock()
		})

		It("should reject token with wrong audience", func() {
			prefix := server.URL + "/realms/SOT_"
			pv := NewPrefixVerifier(PrefixVerifierOptions{
				Prefix:         prefix,
				Audience:       "my-client",
				AudienceClaims: []string{"aud"},
			})

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": issuerURL,
				"sub": "user-1",
				"aud": "wrong-client",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			token.Header["kid"] = "test-key-1"
			signed, err := token.SignedString(privateKey)
			Expect(err).ToNot(HaveOccurred())

			_, err = pv.Verify(context.Background(), signed)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("audience"))
		})

		It("should reject an expired token", func() {
			prefix := server.URL + "/realms/SOT_"
			pv := NewPrefixVerifier(PrefixVerifierOptions{
				Prefix:         prefix,
				Audience:       "my-client",
				AudienceClaims: []string{"aud"},
			})

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": issuerURL,
				"sub": "user-1",
				"aud": "my-client",
				"exp": time.Now().Add(-time.Hour).Unix(),
			})
			token.Header["kid"] = "test-key-1"
			signed, err := token.SignedString(privateKey)
			Expect(err).ToNot(HaveOccurred())

			_, err = pv.Verify(context.Background(), signed)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to verify token"))
		})

		It("should reject token signed with wrong key", func() {
			prefix := server.URL + "/realms/SOT_"
			pv := NewPrefixVerifier(PrefixVerifierOptions{
				Prefix:         prefix,
				Audience:       "my-client",
				AudienceClaims: []string{"aud"},
			})

			// Generate a different key
			wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).ToNot(HaveOccurred())

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": issuerURL,
				"sub": "user-1",
				"aud": "my-client",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			token.Header["kid"] = "test-key-1"
			signed, err := token.SignedString(wrongKey)
			Expect(err).ToNot(HaveOccurred())

			_, err = pv.Verify(context.Background(), signed)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to verify token"))
		})
	})

	Context("prefix matching security", func() {
		It("should not match partial prefix overlaps", func() {
			pv := NewPrefixVerifier(PrefixVerifierOptions{
				Prefix:         "https://keycloak.example.com/realms/SOT_",
				Audience:       "my-client",
				AudienceClaims: []string{"aud"},
			})

			// Issuer that looks similar but comes from a different host
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": "https://keycloak.example.com.evil.com/realms/SOT_HACK",
				"sub": "user-1",
				"aud": "my-client",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			token.Header["kid"] = "test-key-1"
			signed, err := token.SignedString(privateKey)
			Expect(err).ToNot(HaveOccurred())

			_, err = pv.Verify(context.Background(), signed)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("does not match prefix"))
		})

		It("should match exact prefix boundary", func() {
			pv := NewPrefixVerifier(PrefixVerifierOptions{
				Prefix:         server.URL + "/realms/SOT_",
				Audience:       "my-client",
				AudienceClaims: []string{"aud"},
			})

			// SOT_TENANT_A starts with SOT_ ✓
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": issuerURL, // ends with /realms/SOT_TENANT_A
				"sub": "user-1",
				"aud": "my-client",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			token.Header["kid"] = "test-key-1"
			signed, err := token.SignedString(privateKey)
			Expect(err).ToNot(HaveOccurred())

			idToken, err := pv.Verify(context.Background(), signed)
			Expect(err).ToNot(HaveOccurred())
			Expect(idToken.Issuer).To(Equal(issuerURL))
		})
	})
})

// Suppress unused import warnings
var _ = fmt.Sprintf
var _ = strings.HasPrefix
