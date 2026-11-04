package validation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateExtraJWTIssuerSigningAlgorithms(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name        string
		discovery   bool
		discovered  []string
		configured  []string
		wantError   bool
		rejectES256 bool
	}{
		{"discovery", true, []string{"ES256", "RS256"}, []string{"ES256"}, false, false},
		{"fallback", false, nil, []string{"ES256"}, false, false},
		{"disjoint algorithms", true, []string{"RS256"}, []string{"ES256"}, true, false},
		{"discovery defaults", true, []string{"ES256"}, nil, false, false},
		{"discovery restricts algorithms", true, []string{"ES256", "RS256"}, []string{"RS256"}, false, true},
		{"fallback restricts algorithms", false, nil, []string{"RS256"}, false, true},
		{"fallback defaults to RS256", false, nil, nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var discoveryRequests, discoveredKeysRequests, fallbackKeysRequests atomic.Int32
			var issuer string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					discoveryRequests.Add(1)
					if !tc.discovery {
						http.NotFound(w, r)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"issuer":                                issuer,
						"jwks_uri":                              issuer + "/discovered-keys",
						"id_token_signing_alg_values_supported": tc.discovered,
					})
				case "/discovered-keys", "/.well-known/jwks.json":
					if r.URL.Path == "/discovered-keys" {
						discoveredKeysRequests.Add(1)
					} else {
						fallbackKeysRequests.Add(1)
					}
					_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
						{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "ES256", Use: "sig"},
					}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			issuer = server.URL

			o := testOptions()
			o.SkipJwtBearerTokens = true
			o.ExtraJwtIssuers = []string{issuer + "=extra-client"}
			o.Providers[0].OIDCConfig.EnabledSigningAlgs = tc.configured
			err := Validate(o)
			assert.EqualValues(t, 1, discoveryRequests.Load())
			if tc.wantError {
				require.ErrorContains(t, err, "no supported signing algorithms in common")
				assert.ErrorContains(t, err, "discovered=[RS256], configured=[ES256]")
				assert.Zero(t, fallbackKeysRequests.Load())
				return
			}
			require.NoError(t, err)
			require.Len(t, o.GetJWTBearerVerifiers(), 1)
			verifier := o.GetJWTBearerVerifiers()[0]
			for _, tokenCase := range []struct {
				name     string
				issuer   string
				audience string
				key      *ecdsa.PrivateKey
				valid    bool
			}{
				{"valid ES256", issuer, "extra-client", key, true},
				{"wrong audience", issuer, "wrong-client", key, false},
				{"wrong issuer", issuer + "/other", "extra-client", key, false},
				{"wrong signature", issuer, "extra-client", otherKey, false},
			} {
				t.Run(tokenCase.name, func(t *testing.T) {
					signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: tokenCase.key},
						(&jose.SignerOptions{}).WithHeader("kid", "test-key"))
					require.NoError(t, err)
					token, err := jwt.Signed(signer).Claims(jwt.Claims{
						Issuer: tokenCase.issuer, Subject: "test-user",
						Audience: jwt.Audience{tokenCase.audience},
						Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
					}).Serialize()
					require.NoError(t, err)
					verified, err := verifier.Verify(context.Background(), token)
					if tokenCase.valid && !tc.rejectES256 {
						require.NoError(t, err)
						assert.Equal(t, "test-user", verified.Subject)
					} else {
						require.Error(t, err)
					}
				})
			}
			if tc.rejectES256 {
				assert.Zero(t, discoveredKeysRequests.Load())
				assert.Zero(t, fallbackKeysRequests.Load())
			} else if tc.discovery {
				assert.Positive(t, discoveredKeysRequests.Load())
				assert.Zero(t, fallbackKeysRequests.Load())
			} else {
				assert.Zero(t, discoveredKeysRequests.Load())
				assert.Positive(t, fallbackKeysRequests.Load())
			}
		})
	}
}
