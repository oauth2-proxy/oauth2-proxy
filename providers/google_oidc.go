package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	admin "google.golang.org/api/admin/directory/v1"
)

// GoogleOIDCProvider represents a Google provider with OIDC-compliant ID token verification.
// This provider uses proper cryptographic verification of ID tokens per the OIDC spec,
// including signature verification via Google's JWKS, issuer validation, audience validation,
// and expiration checks.
type GoogleOIDCProvider struct {
	*OIDCProvider

	// adminService is used to fetch user's groups from Google Admin Directory API if configured.
	adminService *admin.Service
}

const (
	googleOIDCProviderName = "Google OIDC"
)

var _ Provider = (*GoogleOIDCProvider)(nil)

// NewGoogleOIDCProvider creates a new GoogleOIDCProvider with OIDC-compliant ID token verification.
func NewGoogleOIDCProvider(p *ProviderData, googleOpts options.GoogleOptions, oidcOpts options.OIDCOptions) *GoogleOIDCProvider {
	// Set Google-specific defaults
	if p.ProviderName == "" {
		p.ProviderName = googleOIDCProviderName
	}

	// Create the underlying OIDC provider
	oidcProvider := NewOIDCProvider(p, oidcOpts)

	provider := &GoogleOIDCProvider{
		OIDCProvider: oidcProvider,
	}

	// Set up Google Admin API for group fetching if credentials are configured
	if googleOpts.ServiceAccountJSON != "" || ptr.Deref(googleOpts.UseApplicationDefaultCredentials, options.DefaultUseApplicationDefaultCredentials) {
		provider.adminService = getAdminService(googleOpts)
	}

	return provider
}

// EnrichSession checks the listed Google Groups configured and adds any
// that the user is a member of to session.Groups.
// It also sets preferredUsername from the 'name' claim in the ID token.
func (p *GoogleOIDCProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// First, call the parent OIDC EnrichSession
	if err := p.OIDCProvider.EnrichSession(ctx, s); err != nil {
		return err
	}

	// Populate session.Groups from Google Admin API
	if err := p.getGroups(s); err != nil {
		return err
	}

	// Set preferredUsername from the 'name' claim in the ID token
	if err := p.setPreferredUsername(s); err != nil {
		logger.Errorf("failed to extract name claim: %v", err)
	}

	return nil
}

// setPreferredUsername extracts the 'name' claim from the ID token
// and sets it as the PreferredUsername. Falls back to session email if name is unavailable.
func (p *GoogleOIDCProvider) setPreferredUsername(s *sessions.SessionState) error {
	extractor, err := p.getClaimExtractor(s.IDToken, s.AccessToken)
	if err != nil {
		return fmt.Errorf("could not get claim extractor: %v", err)
	}

	var name string
	if exists, err := extractor.GetClaimInto("name", &name); err != nil || !exists {
		return fmt.Errorf("name claim not present: %v", err)
	}

	s.PreferredUsername = name

	return nil
}

// getGroups fetches all groups the user belongs to and populates session.Groups.
func (p *GoogleOIDCProvider) getGroups(s *sessions.SessionState) error {
	if p.adminService == nil {
		return nil
	}

	groups, err := getUserGroups(p.adminService, s.Email)
	if err != nil {
		return fmt.Errorf("failed to get user groups for %s: %v", s.Email, err)
	}

	s.Groups = groups
	return nil
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *GoogleOIDCProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	refreshed, err := p.OIDCProvider.RefreshSession(ctx, s)
	if err != nil || !refreshed {
		return refreshed, err
	}

	// Re-populate user's groups from Admin API
	if err := p.getGroups(s); err != nil {
		return false, err
	}

	// Update PreferredUsername from the refreshed ID token
	if err := p.setPreferredUsername(s); err != nil {
		logger.Errorf("failed to extract name claim on refresh: %v", err)
	}

	return true, nil
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *GoogleOIDCProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	ss, err := p.OIDCProvider.CreateSessionFromToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("could not create session from token: %v", err)
	}

	// Populate groups from Google Admin API if configured
	if err := p.getGroups(ss); err != nil {
		return nil, err
	}

	// Set preferredUsername from the 'name' claim
	if err := p.setPreferredUsername(ss); err != nil {
		logger.Errorf("failed to extract name claim from bearer token: %v", err)
	}

	return ss, nil
}

// GetLoginURL makes the LoginURL with optional nonce support
func (p *GoogleOIDCProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	// Add Google-specific parameters for offline access (refresh tokens)
	if extraParams == nil {
		extraParams = url.Values{}
	}
	if extraParams.Get("access_type") == "" {
		extraParams.Set("access_type", "offline")
	}
	return p.OIDCProvider.GetLoginURL(redirectURI, state, nonce, extraParams)
}
