package providers

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// ErrProviderNotReady is returned by a LazyProvider's methods while background
// OIDC discovery has not yet completed. Provider-independent features (such as
// Basic Auth via htpasswd-file) do not go through these methods and therefore
// keep working while discovery is pending.
var ErrProviderNotReady = errors.New("provider not ready: OIDC discovery has not completed yet")

// Background discovery backoff bounds.
const (
	lazyDiscoveryInitialInterval = 3 * time.Second
	lazyDiscoveryMaxInterval     = 30 * time.Second
)

// LazyProvider wraps a Provider whose construction depends on OIDC discovery.
// It starts out not-ready, delegating only Data() to a discovery-independent
// placeholder, and returns ErrProviderNotReady from OAuth flow methods. Once
// background discovery succeeds, the real provider is swapped in atomically and
// all methods delegate to it.
type LazyProvider struct {
	providerConfig options.Provider
	placeholder    Provider

	mu    sync.RWMutex
	inner Provider
}

var _ Provider = (*LazyProvider)(nil)

// NewLazyProvider builds a LazyProvider for the given configuration. The
// placeholder provider is constructed without performing OIDC discovery so it
// cannot fail on an unreachable issuer. Call InitWithRetry (typically in a
// goroutine) to perform discovery in the background.
func NewLazyProvider(providerConfig options.Provider) (*LazyProvider, error) {
	placeholder, err := newPlaceholderProvider(providerConfig)
	if err != nil {
		return nil, err
	}
	return &LazyProvider{
		providerConfig: providerConfig,
		placeholder:    placeholder,
	}, nil
}

// current returns the real provider if discovery has completed, otherwise nil.
func (l *LazyProvider) current() Provider {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.inner
}

// Ready reports whether background discovery has completed and the real
// provider is available.
func (l *LazyProvider) Ready() bool {
	return l.current() != nil
}

func (l *LazyProvider) setInner(p Provider) {
	l.mu.Lock()
	l.inner = p
	l.mu.Unlock()
}

// InitWithRetry repeatedly attempts to construct the real provider (performing
// OIDC discovery) until it succeeds or ctx is cancelled. Once construction
// succeeds the real provider is swapped in and the LazyProvider becomes ready.
// It is intended to be run in a goroutine.
func (l *LazyProvider) InitWithRetry(ctx context.Context) {
	interval := lazyDiscoveryInitialInterval
	attempt := 0
	for {
		attempt++
		provider, err := NewProvider(l.providerConfig)
		if err == nil {
			l.setInner(provider)
			logger.Printf("OIDC discovery succeeded after %d attempt(s); provider is now ready", attempt)
			return
		}
		logger.Errorf("lazy OIDC discovery attempt %d failed, will retry in %s: %v", attempt, interval, err)

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			logger.Errorf("stopping lazy OIDC discovery: %v", ctx.Err())
			return
		case <-timer.C:
		}

		interval *= 2
		if interval > lazyDiscoveryMaxInterval {
			interval = lazyDiscoveryMaxInterval
		}
	}
}

// Data returns the real provider's data once ready, otherwise the placeholder's.
func (l *LazyProvider) Data() *ProviderData {
	if p := l.current(); p != nil {
		return p.Data()
	}
	return l.placeholder.Data()
}

// GetLoginURL returns an empty string until the provider is ready.
func (l *LazyProvider) GetLoginURL(redirectURI, finalRedirect, nonce string, extraParams url.Values) string {
	if p := l.current(); p != nil {
		return p.GetLoginURL(redirectURI, finalRedirect, nonce, extraParams)
	}
	return ""
}

func (l *LazyProvider) Redeem(ctx context.Context, redirectURI, code, codeVerifier string) (*sessions.SessionState, error) {
	if p := l.current(); p != nil {
		return p.Redeem(ctx, redirectURI, code, codeVerifier)
	}
	return nil, ErrProviderNotReady
}

func (l *LazyProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if p := l.current(); p != nil {
		return p.GetEmailAddress(ctx, s)
	}
	return "", ErrProviderNotReady
}

func (l *LazyProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if p := l.current(); p != nil {
		return p.EnrichSession(ctx, s)
	}
	return ErrProviderNotReady
}

func (l *LazyProvider) Authorize(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if p := l.current(); p != nil {
		return p.Authorize(ctx, s)
	}
	return false, ErrProviderNotReady
}

// ValidateSession returns false until the provider is ready.
func (l *LazyProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	if p := l.current(); p != nil {
		return p.ValidateSession(ctx, s)
	}
	return false
}

func (l *LazyProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if p := l.current(); p != nil {
		return p.RefreshSession(ctx, s)
	}
	return false, ErrProviderNotReady
}

func (l *LazyProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	if p := l.current(); p != nil {
		return p.CreateSessionFromToken(ctx, token)
	}
	return nil, ErrProviderNotReady
}
