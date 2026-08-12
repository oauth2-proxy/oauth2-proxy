package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	. "github.com/onsi/gomega"
)

// newLazyPendingProxy builds a proxy whose OIDC issuer is unreachable with lazy
// discovery enabled. Start is not called, so background discovery never runs and
// the provider stays not-ready for the duration of the test.
func newLazyPendingProxy(g *WithT) *OAuthProxy {
	opts := baseTestOptions()
	opts.Providers[0].Type = "oidc"
	opts.Providers[0].OIDCConfig = options.OIDCOptions{
		IssuerURL:      "http://127.0.0.1:1/realms/test",
		SkipDiscovery:  ptr.To(false),
		LazyDiscovery:  ptr.To(true),
		EmailClaim:     options.OIDCEmailClaim,
		AudienceClaims: []string{"aud"},
	}
	g.Expect(validation.Validate(opts)).To(Succeed())

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(proxy.providerReady()).To(BeFalse())
	return proxy
}

func unreachableOIDCProvider(lazy bool) options.Provider {
	return options.Provider{
		ID:       "test-provider",
		Type:     "oidc",
		ClientID: "client-id",
		OIDCConfig: options.OIDCOptions{
			IssuerURL:     "http://127.0.0.1:1/realms/test",
			SkipDiscovery: ptr.To(false),
			LazyDiscovery: ptr.To(lazy),
		},
	}
}

func TestSetupProviderLazyFallback(t *testing.T) {
	g := NewWithT(t)

	// setupProvider does not start the background loop (Start does), so there is
	// no goroutine to cancel here.
	provider, err := setupProvider(unreachableOIDCProvider(true))
	g.Expect(err).ToNot(HaveOccurred())

	lazy, ok := provider.(*providers.LazyProvider)
	g.Expect(ok).To(BeTrue(), "expected a LazyProvider when discovery fails and lazy discovery is enabled")
	g.Expect(lazy.Ready()).To(BeFalse())
}

func TestSetupProviderWithoutLazyFailsFast(t *testing.T) {
	g := NewWithT(t)

	_, err := setupProvider(unreachableOIDCProvider(false))
	g.Expect(err).To(HaveOccurred())
}

// TestReadyEndpointOKWhenProviderNotReady ensures /ready stays healthy under
// lazy discovery so the pod remains in load-balancer rotation while discovery
// is still pending.
func TestReadyEndpointOKWhenProviderNotReady(t *testing.T) {
	g := NewWithT(t)

	proxy := newLazyPendingProxy(g)

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	proxy.ServeHTTP(rw, req)

	g.Expect(rw.Code).To(Equal(http.StatusOK))
}

// TestOAuthStartUnavailableWhenProviderNotReady ensures the OAuth2 login flow
// returns 503 (rather than a silent self-redirect loop) while lazy discovery is
// still pending.
func TestOAuthStartUnavailableWhenProviderNotReady(t *testing.T) {
	g := NewWithT(t)

	proxy := newLazyPendingProxy(g)

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth2/start", nil)
	proxy.ServeHTTP(rw, req)

	g.Expect(rw.Code).To(Equal(http.StatusServiceUnavailable))
}
