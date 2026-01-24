package providers

import (
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
	"golang.org/x/oauth2"
)

const (
	appleProviderName = "Apple"
	appleDefaultScope = "openid email name"

	appleAudience = "https://appleid.apple.com"
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
// This provider is only configurable via AlphaConfig.
// See: https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api
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

	provider := &AppleProvider{
		OIDCProvider: &OIDCProvider{
			ProviderData: p,
			SkipNonce:    true, // Apple doesn't use nonce in the standard way
			AuthStyle:    oauth2.AuthStyleInParams, // Apple requires credentials in POST body
		},
		TeamID: appleOpts.TeamID,
		KeyID:  appleOpts.KeyID,
	}

	if err := provider.initialize(appleOpts); err != nil {
		return nil, fmt.Errorf("could not initialize Apple provider: %v", err)
	}

	// Set up dynamic client secret generation
	// Apple requires client_secret to be a JWT signed with ES256
	p.ClientSecretFunc = provider.generateClientSecret

	return provider, nil
}

// initialize validates and configures the Apple provider with the private key
func (p *AppleProvider) initialize(opts options.AppleOptions) error {
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
// See: https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
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
// See: https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
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

// ValidateSession validates the session's ID token
func (p *AppleProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	ctx = oidc.ClientContext(ctx, requests.DefaultHTTPClient)

	// Validate ID token if present
	if s.IDToken != "" && p.Verifier != nil {
		if _, err := p.Verifier.Verify(ctx, s.IDToken); err != nil {
			return false
		}
		// ID token is valid - Apple doesn't provide a token validation endpoint
		return true
	}

	// Fallback to access token validation if ValidateURL is set
	if p.ValidateURL != nil && p.ValidateURL.String() != "" {
		return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
	}

	// No validation possible, but session exists with valid data
	return s.AccessToken != ""
}
