package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// NewClientCertificateSessionLoader authenticates a verified client certificate
// when it matches an explicitly configured fingerprint. Requests without a
// certificate continue through the normal OIDC and session loaders.
func NewClientCertificateSessionLoader(identities []options.ClientIdentity) func(http.Handler) http.Handler {
	identityByFingerprint := make(map[string]options.ClientIdentity, len(identities))
	for _, identity := range identities {
		fingerprint := strings.ReplaceAll(strings.ToLower(identity.Fingerprint), ":", "")
		identityByFingerprint[fingerprint] = identity
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			scope := middlewareapi.GetRequestScope(req)
			if scope.Session != nil || req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.VerifiedChains[0]) == 0 {
				next.ServeHTTP(rw, req)
				return
			}

			now := time.Now()
			expiresOn := req.TLS.VerifiedChains[0][0].NotAfter
			for _, cert := range req.TLS.VerifiedChains[0] {
				if cert.NotAfter.Before(expiresOn) {
					expiresOn = cert.NotAfter
				}
				if cert.NotBefore.After(now) || cert.NotAfter.Before(now) {
					http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
					return
				}
			}
			cert := req.TLS.VerifiedChains[0][0]
			digest := sha256.Sum256(cert.Raw)
			identity, ok := identityByFingerprint[hex.EncodeToString(digest[:])]
			if !ok {
				http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}

			scope.Session = &sessions.SessionState{
				CreatedAt:         &now,
				ExpiresOn:         &expiresOn,
				User:              identity.User,
				Email:             identity.Email,
				Groups:            append([]string(nil), identity.Groups...),
				PreferredUsername: identity.PreferredUsername,
			}
			next.ServeHTTP(rw, req)
		})
	}
}
