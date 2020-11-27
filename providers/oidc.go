package providers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"golang.org/x/oauth2"
)

const emailClaim = "email"

// OIDCProvider represents an OIDC based Identity Provider
type OIDCProvider struct {
	*ProviderData

	AllowUnverifiedEmail bool
	EmailClaim           string
	GroupsClaim          string
}

// NewOIDCProvider initiates a new OIDCProvider
func NewOIDCProvider(p *ProviderData) *OIDCProvider {
	p.ProviderName = "OpenID Connect"
	return &OIDCProvider{ProviderData: p}
}

var _ Provider = (*OIDCProvider)(nil)

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *OIDCProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failure: %v", err)
	}

	return p.createSession(ctx, token, false)
}

// EnrichSessionState is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *OIDCProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if p.ProfileURL.String() == "" {
		if s.Email == "" {
			return errors.New("id_token did not contain an email and profileURL is not defined")
		}
		return nil
	}

	// Try to get missing emails or groups from a profileURL
	if s.Email == "" || len(s.Groups) == 0 {
		err := p.callProfileURL(ctx, s)
		if err != nil {
			logger.Errorf("Warning: Profile URL request failed: %v", err)
		}
	}

	// If a mandatory email wasn't set, error at this point.
	if s.Email == "" {
		return errors.New("neither the id_token nor the profileURL set an email")
	}
	return nil
}

// callProfileURL enriches a session's Email & Groups via the JSON response of
// an OIDC profile URL
func (p *OIDCProvider) callProfileURL(ctx context.Context, s *sessions.SessionState) error {
	respJSON, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return err
	}

	email, err := respJSON.Get(p.EmailClaim).String()
	if err == nil && s.Email == "" {
		s.Email = email
	}

	// Handle array & singleton groups cases
	if len(s.Groups) == 0 {
		groups, err := respJSON.Get(p.GroupsClaim).StringArray()
		if err == nil {
			s.Groups = groups
		} else {
			group, err := respJSON.Get(p.GroupsClaim).String()
			if err == nil {
				s.Groups = []string{group}
			}
		}
	}

	return nil
}

// ValidateSessionState checks that the session's IDToken is still valid
func (p *OIDCProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	return err == nil
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new Access Token (and optional ID token) if required
func (p *OIDCProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || (s.ExpiresOn != nil && s.ExpiresOn.After(time.Now())) || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	logger.Printf("refreshed session: %s", s)
	return true, nil
}

// redeemRefreshToken uses a RefreshToken with the RedeemURL to refresh the
// Access Token and (probably) the ID Token.
func (p *OIDCProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}

	newSession, err := p.createSession(ctx, token, true)
	if err != nil {
		return fmt.Errorf("unable create new session state from response: %v", err)
	}

	// It's possible that if the refresh token isn't in the token response the
	// session will not contain an id token.
	// If it doesn't it's probably better to retain the old one
	if newSession.IDToken != "" {
		s.IDToken = newSession.IDToken
		s.Email = newSession.Email
		s.User = newSession.User
		s.Groups = newSession.Groups
		s.PreferredUsername = newSession.PreferredUsername
	}

	s.AccessToken = newSession.AccessToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn

	return nil
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *OIDCProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	idToken, err := p.Verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	ss, err := p.buildSessionFromClaims(idToken)
	if err != nil {
		return nil, err
	}

	// Allow empty Email in Bearer case since we can't hit the ProfileURL
	if ss.Email == "" {
		ss.Email = ss.User
	}

	ss.AccessToken = token
	ss.IDToken = token
	ss.RefreshToken = ""
	ss.ExpiresOn = &idToken.Expiry

	return ss, nil
}

// createSession takes an oauth2.Token and creates a SessionState from it.
// It alters behavior if called from Redeem vs Refresh
func (p *OIDCProvider) createSession(ctx context.Context, token *oauth2.Token, refresh bool) (*sessions.SessionState, error) {
	idToken, err := p.findVerifiedIDToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// IDToken is mandatory in Redeem but optional in Refresh
	if idToken == nil && !refresh {
		return nil, errors.New("token response did not contain an id_token")
	}

	ss, err := p.buildSessionFromClaims(idToken)
	if err != nil {
		return nil, err
	}

	ss.AccessToken = token.AccessToken
	ss.RefreshToken = token.RefreshToken
	ss.IDToken = getIDToken(token)

	created := time.Now()
	ss.CreatedAt = &created
	ss.ExpiresOn = &token.Expiry

	return ss, nil
}

func (p *OIDCProvider) findVerifiedIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken := getIDToken(token)
	if strings.TrimSpace(rawIDToken) != "" {
		return p.Verifier.Verify(ctx, rawIDToken)
	}
	return nil, nil
}

// buildSessionFromClaims uses IDToken claims to populate a fresh SessionState
// with non-Token related fields.
func (p *OIDCProvider) buildSessionFromClaims(idToken *oidc.IDToken) (*sessions.SessionState, error) {
	ss := &sessions.SessionState{}

	if idToken == nil {
		return ss, nil
	}

	claims, err := p.getClaims(idToken)
	if err != nil {
		return nil, fmt.Errorf("couldn't extract claims from id_token (%v)", err)
	}

	ss.User = claims.Subject
	ss.Email = claims.Email
	ss.Groups = claims.Groups

	// TODO (@NickMeves) Deprecate for dynamic claim to session mapping
	if pref, ok := claims.rawClaims["preferred_username"].(string); ok {
		ss.PreferredUsername = pref
	}

	verifyEmail := (p.EmailClaim == emailClaim) && !p.AllowUnverifiedEmail
	if verifyEmail && claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	return ss, nil
}

type OIDCClaims struct {
	Subject  string   `json:"sub"`
	Email    string   `json:"-"`
	Groups   []string `json:"-"`
	Verified *bool    `json:"email_verified"`

	rawClaims map[string]interface{}
}

// getClaims extracts IDToken claims into an OIDCClaims
func (p *OIDCProvider) getClaims(idToken *oidc.IDToken) (*OIDCClaims, error) {
	claims := &OIDCClaims{}

	// Extract default claims.
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse default id_token claims: %v", err)
	}
	// Extract custom claims.
	if err := idToken.Claims(&claims.rawClaims); err != nil {
		return nil, fmt.Errorf("failed to parse all id_token claims: %v", err)
	}

	email := claims.rawClaims[p.EmailClaim]
	if email != nil {
		claims.Email = fmt.Sprint(email)
	}
	claims.Groups = p.extractGroups(claims.rawClaims)

	return claims, nil
}

func (p *OIDCProvider) extractGroups(claims map[string]interface{}) []string {
	groups := []string{}
	rawGroups, ok := claims[p.GroupsClaim].([]interface{})
	if rawGroups != nil && ok {
		for _, rawGroup := range rawGroups {
			formattedGroup, err := formatGroup(rawGroup)
			if err != nil {
				logger.Errorf("Warning: unable to format group of type %s with error %s",
					reflect.TypeOf(rawGroup), err)
				continue
			}
			groups = append(groups, formattedGroup)
		}
	}
	return groups
}
