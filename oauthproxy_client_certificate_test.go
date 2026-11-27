package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Listener tests establish VerifiedChains; exercise the application stack here.
func TestClientCertificateOAuthProxyRoutes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	serverDER, serverKey, err := util.GenerateCert("127.0.0.1")
	require.NoError(t, err)
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKey})
	cert := &x509.Certificate{Raw: []byte("mapped"), NotAfter: now.Add(time.Hour)}
	digest := sha256.Sum256(cert.Raw)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, []string{r.Header.Get("X-Expected-User")}, r.Header.Values("X-Forwarded-User"))
		assert.NotContains(t, r.Header, "X_Forwarded_User")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	for _, tc := range []struct {
		name   string
		cert   *x509.Certificate
		cookie bool
		email  string
		groups []string
		user   string
		status int
	}{
		{name: "mapped certificate", cert: cert, email: "client@example.com", groups: []string{"operators"}, user: "client"},
		{name: "mapped certificate takes precedence over cookie", cert: cert, cookie: true, email: "client@example.com", groups: []string{"operators"}, user: "client"},
		{name: "unmapped certificate rejects valid cookie", cert: &x509.Certificate{Raw: []byte("unmapped"), NotAfter: cert.NotAfter}, cookie: true, status: http.StatusForbidden},
		{name: "certificate email authorization", cert: cert, email: "denied@example.com", groups: []string{"operators"}, status: http.StatusForbidden},
		{name: "certificate group authorization", cert: cert, email: "client@example.com", groups: []string{"denied"}, status: http.StatusForbidden},
		{name: "no certificate uses OIDC cookie", cookie: true, user: "oidc"},
		{name: "no certificate or cookie requires login", status: http.StatusForbidden},
	} {
		for _, route := range []string{"/", "/oauth2/auth"} {
			t.Run(tc.name+route, func(t *testing.T) {
				opts := baseTestOptions()
				opts.Providers[0].Type = options.OIDCProvider
				opts.Providers[0].LoginURL = "https://oidc.example.com/authorize"
				opts.Providers[0].RedeemURL = "https://oidc.example.com/token"
				opts.Providers[0].OIDCConfig.IssuerURL = "https://oidc.example.com"
				opts.Providers[0].OIDCConfig.JwksURL = "https://oidc.example.com/keys"
				opts.Providers[0].OIDCConfig.SkipDiscovery = ptr.To(true)
				opts.Providers[0].AllowedGroups = []string{"operators"}
				opts.UpstreamServers.Upstreams = []options.Upstream{{ID: "upstream", Path: "/", URI: upstream.URL}}
				opts.InjectResponseHeaders = []options.Header{
					{Name: "X-Session-User", Values: []options.HeaderValue{{ClaimSource: &options.ClaimSource{Claim: "user"}}}},
					{Name: "X-Created-At", Values: []options.HeaderValue{{ClaimSource: &options.ClaimSource{Claim: "created_at"}}}},
					{Name: "X-Expires-On", Values: []options.HeaderValue{{ClaimSource: &options.ClaimSource{Claim: "expires_on"}}}},
				}
				opts.Server.BindAddress = ""
				opts.Server.SecureBindAddress = "127.0.0.1:0"
				opts.Server.TLS = &options.TLS{Cert: &options.SecretSource{Value: serverPEM}, Key: &options.SecretSource{Value: serverKeyPEM}, ClientCA: &options.SecretSource{Value: serverPEM}, ClientIdentities: []options.ClientIdentity{{Fingerprint: hex.EncodeToString(digest[:]), User: "client", Email: tc.email, Groups: tc.groups}}}
				require.NoError(t, validation.Validate(opts))
				proxy, err := NewOAuthProxy(opts, func(email string) bool { return email != "denied@example.com" })
				require.NoError(t, err)
				t.Cleanup(func() {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					require.NoError(t, proxy.server.Start(ctx))
				})
				req := httptest.NewRequest(http.MethodGet, route, nil)
				if tc.cert != nil {
					req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{tc.cert}}}
				}
				if tc.cookie {
					cookieResponse := httptest.NewRecorder()
					require.NoError(t, proxy.SaveSession(cookieResponse, req, &sessions.SessionState{User: "oidc", Email: "oidc@example.com", Groups: []string{"operators"}, CreatedAt: &now, ExpiresOn: &cert.NotAfter}))
					for _, cookie := range cookieResponse.Result().Cookies() {
						req.AddCookie(cookie)
					}
				}
				req.Header.Set("X-Forwarded-User", "spoofed")
				req.Header.Set("X_Forwarded_User", "spoofed")
				req.Header.Set("X-Expected-User", tc.user)
				rw := httptest.NewRecorder()
				proxy.ServeHTTP(rw, req)
				expectedStatus := tc.status
				if expectedStatus == 0 {
					expectedStatus = http.StatusOK
					if route == "/oauth2/auth" {
						expectedStatus = http.StatusAccepted
					}
					require.Equal(t, tc.user, rw.Header().Get("X-Session-User"))
					require.NotEmpty(t, rw.Header().Get("X-Created-At"))
					expiresOn, err := time.Parse("2006-01-02 15:04:05 -0700 MST", rw.Header().Get("X-Expires-On"))
					require.NoError(t, err)
					require.True(t, cert.NotAfter.Equal(expiresOn))
					require.Empty(t, rw.Result().Cookies(), "authentication must not persist a certificate identity or refresh the existing cookie")
				} else if route == "/oauth2/auth" && (tc.cert == cert || tc.cert == nil) {
					expectedStatus = http.StatusUnauthorized
				}
				require.Equal(t, expectedStatus, rw.Code)
			})
		}
	}
}
