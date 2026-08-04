package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	. "github.com/onsi/gomega"
)

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

func TestProviderReadinessVerifier(t *testing.T) {
	g := NewWithT(t)

	// A non-lazy provider (google needs no discovery) is always considered ready.
	nonLazy, err := providers.NewProvider(options.Provider{ID: "g", Type: "google", ClientID: "client-id"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(providerReadiness{provider: nonLazy}.VerifyConnection(context.Background())).To(Succeed())

	// A lazy provider that has not completed discovery is not ready.
	lazy, err := providers.NewLazyProvider(unreachableOIDCProvider(true))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(providerReadiness{provider: lazy}.VerifyConnection(context.Background())).ToNot(Succeed())
}

// TestOAuthStartUnavailableWhenProviderNotReady ensures the OAuth2 login flow
// returns 503 (rather than a silent self-redirect loop) while lazy discovery is
// still pending.
func TestOAuthStartUnavailableWhenProviderNotReady(t *testing.T) {
	g := NewWithT(t)

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

	// Not calling Start, so background discovery never runs and the provider
	// stays not-ready for the duration of the test.
	proxy, err := NewOAuthProxy(opts, func(string) bool { return true })
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(proxy.providerReady()).To(BeFalse())

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth2/start", nil)
	proxy.ServeHTTP(rw, req)

	g.Expect(rw.Code).To(Equal(http.StatusServiceUnavailable))
}
