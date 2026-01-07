package providers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

const (
	appleProviderName = "Apple"
	appleDefaultScope = "openid email name"

	appleIssuerURL = "https://appleid.apple.com"
	appleAuthURL   = "https://appleid.apple.com/auth/authorize"
	appleTokenURL  = "https://appleid.apple.com/auth/token"
	appleAudience  = "https://appleid.apple.com"
)

var (
	appleDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "appleid.apple.com",
		Path:   "/auth/authorize",
	}

	appleDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "appleid.apple.com",
		Path:   "/auth/token",
	}
)

// AppleProvider represents the Apple Sign in with Apple OIDC provider
type AppleProvider struct {
	*OIDCProvider

	TeamID     string
	KeyID      string
	PrivateKey *ecdsa.PrivateKey
}

var _ Provider = (*AppleProvider)(nil)

// NewAppleProvider creates a new AppleProvider
func NewAppleProvider(p *ProviderData, appleOpts options.AppleOptions, oidcOpts options.OIDCOptions) (*AppleProvider, error) {
	p.setProviderDefaults(providerDefaults{
		name:        appleProviderName,
		loginURL:    appleDefaultLoginURL,
		redeemURL:   appleDefaultRedeemURL,
		profileURL:  nil,
		validateURL: nil,
		scope:       appleDefaultScope,
	})
	p.getAuthorizationHeaderFunc = makeOIDCHeader

	oidcProvider := &OIDCProvider{
		ProviderData: p,
		SkipNonce:    true, // Apple doesn't use nonce in the standard way
	}

	provider := &AppleProvider{
		OIDCProvider: oidcProvider,
		TeamID:       appleOpts.TeamID,
		KeyID:        appleOpts.KeyID,
	}

	if err := provider.configure(appleOpts); err != nil {
		return nil, fmt.Errorf("could not configure Apple provider: %v", err)
	}

	return provider, nil
}

// configure validates and sets up the Apple provider with the private key
func (p *AppleProvider) configure(opts options.AppleOptions) error {
	if opts.TeamID == "" {
		return errors.New("apple provider requires teamID")
	}
	if opts.KeyID == "" {
		return errors.New("apple provider requires keyID")
	}

	// Private key can be supplied via config or file, but not both
	switch {
	case opts.PrivateKey != "" && opts.PrivateKeyFile != "":
		return errors.New("cannot set both privateKey and privateKeyFile options")
	case opts.PrivateKey == "" && opts.PrivateKeyFile == "":
		return errors.New("apple provider requires a private key for signing JWTs")
	case opts.PrivateKey != "":
		key, err := parseECPrivateKey([]byte(opts.PrivateKey))
		if err != nil {
			return fmt.Errorf("could not parse EC private key: %v", err)
		}
		p.PrivateKey = key
	case opts.PrivateKeyFile != "":
		keyData, err := os.ReadFile(opts.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("could not read private key file %s: %v", opts.PrivateKeyFile, err)
		}
		key, err := parseECPrivateKey(keyData)
		if err != nil {
			return fmt.Errorf("could not parse private key from file %s: %v", opts.PrivateKeyFile, err)
		}
		p.PrivateKey = key
	}

	return nil
}

// parseECPrivateKey parses a PEM-encoded EC private key (Apple .p8 format)
func parseECPrivateKey(keyData []byte) (*ecdsa.PrivateKey, error) {
	// Apple .p8 files contain a PEM-encoded PKCS#8 private key
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Try PKCS#8 first (Apple's format)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
		return nil, errors.New("key is not an EC private key")
	}

	// Fall back to EC private key format
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %v", err)
	}

	return ecKey, nil
}

// generateClientSecret creates a JWT client_secret for Apple token requests
// Apple requires the client_secret to be a JWT signed with ES256
func (p *AppleProvider) generateClientSecret() (string, error) {
	now := time.Now()
	claims := &jwt.RegisteredClaims{
		Issuer:    p.TeamID,
		Subject:   p.ClientID,
		Audience:  jwt.ClaimStrings{appleAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), // Short-lived for security
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = p.KeyID

	return token.SignedString(p.PrivateKey)
}

// GetLoginURL returns the Apple authorization URL with required parameters
func (p *AppleProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	// Apple requires response_mode=form_post for web clients
	if extraParams.Get("response_mode") == "" {
		extraParams.Set("response_mode", "form_post")
	}
	return p.OIDCProvider.GetLoginURL(redirectURI, state, nonce, extraParams)
}

// Redeem exchanges the authorization code for tokens
func (p *AppleProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}

	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %v", err)
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	params.Add("redirect_uri", redirectURL)
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %v", err)
	}

	ctx = oidc.ClientContext(ctx, requests.DefaultHTTPClient)

	// Build session from ID token claims
	ss, err := p.buildSessionFromClaims(jsonResponse.IDToken, jsonResponse.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to build session from claims: %v", err)
	}

	ss.AccessToken = jsonResponse.AccessToken
	ss.RefreshToken = jsonResponse.RefreshToken
	ss.IDToken = jsonResponse.IDToken

	ss.CreatedAtNow()
	ss.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

	return ss, nil
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *AppleProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return false, fmt.Errorf("failed to generate client secret: %v", err)
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("grant_type", "refresh_token")
	params.Add("refresh_token", s.RefreshToken)

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return false, fmt.Errorf("refresh token failed: %v", err)
	}

	// Update session with new tokens
	if jsonResponse.IDToken != "" {
		ctx = oidc.ClientContext(ctx, requests.DefaultHTTPClient)
		newSession, err := p.buildSessionFromClaims(jsonResponse.IDToken, jsonResponse.AccessToken)
		if err == nil {
			s.Email = newSession.Email
			s.User = newSession.User
			s.Groups = newSession.Groups
			s.PreferredUsername = newSession.PreferredUsername
		}
		s.IDToken = jsonResponse.IDToken
	}

	s.AccessToken = jsonResponse.AccessToken
	if jsonResponse.RefreshToken != "" {
		s.RefreshToken = jsonResponse.RefreshToken
	}

	s.CreatedAtNow()
	s.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

	return true, nil
}

// ValidateSession validates the session's ID token
func (p *AppleProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	ctx = oidc.ClientContext(ctx, requests.DefaultHTTPClient)

	// Validate ID token if present
	if s.IDToken != "" && p.Verifier != nil {
		if _, err := p.Verifier.Verify(ctx, s.IDToken); err != nil {
			return false
		}
		// ID token is valid - Apple doesn't provide a token validation endpoint,
		return true
	}

	// Fallback to access token validation if ValidateURL is set
	if p.ValidateURL != nil && p.ValidateURL.String() != "" {
		return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
	}

	// No validation possible, but session exists with valid data
	return s.AccessToken != ""
}
