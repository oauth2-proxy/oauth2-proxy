package providers

import (
	"context"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/mockoidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	. "github.com/onsi/gomega"
)

// unreachableLazyConfig builds an OIDC provider config pointing at an
// unreachable issuer, with lazy discovery enabled.
func unreachableLazyConfig() options.Provider {
	return options.Provider{
		ID:       providerID,
		Type:     "oidc",
		ClientID: clientID,
		OIDCConfig: options.OIDCOptions{
			// Port 1 is not listenable, so discovery fails fast.
			IssuerURL:      "http://127.0.0.1:1/realms/test",
			SkipDiscovery:  ptr.To(false),
			LazyDiscovery:  ptr.To(true),
			AudienceClaims: []string{"aud"},
		},
	}
}

func TestLazyProviderNotReadyGating(t *testing.T) {
	g := NewWithT(t)

	lazy, err := NewLazyProvider(unreachableLazyConfig())
	g.Expect(err).ToNot(HaveOccurred())

	// Not ready until background discovery completes.
	g.Expect(lazy.Ready()).To(BeFalse())

	// Data() serves the discovery-independent placeholder.
	g.Expect(lazy.Data()).ToNot(BeNil())
	g.Expect(lazy.Data().ProviderName).To(Equal("OpenID Connect"))

	// OAuth-flow methods report not-ready rather than panicking.
	g.Expect(lazy.GetLoginURL("https://rd", "", "", url.Values{})).To(BeEmpty())
	g.Expect(lazy.ValidateSession(context.Background(), nil)).To(BeFalse())

	_, err = lazy.Redeem(context.Background(), "https://rd", "code", "")
	g.Expect(err).To(MatchError(ErrProviderNotReady))

	_, err = lazy.GetEmailAddress(context.Background(), nil)
	g.Expect(err).To(MatchError(ErrProviderNotReady))

	err = lazy.EnrichSession(context.Background(), nil)
	g.Expect(err).To(MatchError(ErrProviderNotReady))

	_, err = lazy.Authorize(context.Background(), nil)
	g.Expect(err).To(MatchError(ErrProviderNotReady))

	_, err = lazy.RefreshSession(context.Background(), nil)
	g.Expect(err).To(MatchError(ErrProviderNotReady))

	_, err = lazy.CreateSessionFromToken(context.Background(), "token")
	g.Expect(err).To(MatchError(ErrProviderNotReady))
}

func TestLazyProviderBecomesReady(t *testing.T) {
	g := NewWithT(t)

	m, err := mockoidc.Run()
	g.Expect(err).ToNot(HaveOccurred())
	defer func() {
		g.Expect(m.Shutdown()).To(Succeed())
	}()

	providerConfig := options.Provider{
		ID:       providerID,
		Type:     "oidc",
		ClientID: m.Config().ClientID,
		OIDCConfig: options.OIDCOptions{
			IssuerURL:      m.Issuer(),
			SkipDiscovery:  ptr.To(false),
			LazyDiscovery:  ptr.To(true),
			AudienceClaims: []string{"aud"},
		},
	}

	lazy, err := NewLazyProvider(providerConfig)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(lazy.Ready()).To(BeFalse())

	// The issuer is reachable, so discovery succeeds on the first attempt and
	// InitWithRetry returns promptly.
	lazy.InitWithRetry(context.Background())

	g.Expect(lazy.Ready()).To(BeTrue())
	// Once ready, delegation to the real provider works.
	g.Expect(lazy.GetLoginURL("https://rd", "", "nonce", url.Values{})).ToNot(BeEmpty())
}

func TestLazyProviderInitWithRetryStopsOnContextCancel(t *testing.T) {
	g := NewWithT(t)

	lazy, err := NewLazyProvider(unreachableLazyConfig())
	g.Expect(err).ToNot(HaveOccurred())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		lazy.InitWithRetry(ctx)
		close(done)
	}()

	cancel()

	g.Eventually(done, "2s").Should(BeClosed())
	g.Expect(lazy.Ready()).To(BeFalse())
}
