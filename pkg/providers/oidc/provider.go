package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// providerJSON represents the information we need from an OIDC discovery
type providerJSON struct {
	Issuer               string   `json:"issuer"`
	AuthURL              string   `json:"authorization_endpoint"`
	TokenURL             string   `json:"token_endpoint"`
	JWKsURL              string   `json:"jwks_uri"`
	UserInfoURL          string   `json:"userinfo_endpoint"`
	CodeChallengeAlgs    []string `json:"code_challenge_methods_supported"`
	SupportedSigningAlgs []string `json:"id_token_signing_alg_values_supported"`
}

// Endpoints represents the endpoints discovered as part of the OIDC discovery process
// that will be used by the authentication providers.
type Endpoints struct {
	AuthURL     string
	TokenURL    string
	JWKsURL     string
	UserInfoURL string
}

// PKCE holds information relevant to the PKCE (code challenge) support of the
// provider.
type PKCE struct {
	CodeChallengeAlgs []string
}

// DiscoveryProvider holds information about an identity provider having
// used OIDC discovery to retrieve the information.
type DiscoveryProvider interface {
	Endpoints() Endpoints
	PKCE() PKCE
	SupportedSigningAlgs() []string
}

// NewProvider allows a user to perform an OIDC discovery and returns the DiscoveryProvider.
// We implement this here as opposed to using oidc.Provider so that we can override the Issuer verification check.
// As we have our own verifier and fetch the userinfo separately, the rest of the oidc.Provider implementation is not
// useful to us.
func NewProvider(ctx context.Context, issuerURL string, skipIssuerVerification bool) (DiscoveryProvider, error) {
	// go-oidc doesn't let us pass bypass the issuer check this in the oidc.NewProvider call
	// (which uses discovery to get the URLs), so we'll do a quick check ourselves and if
	// we get the URLs, we'll just use the non-discovery path.

	logger.Printf("Performing OIDC Discovery...")

	var p providerJSON
	requestURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	if err := requests.New(requestURL).WithClientFromContext(ctx).Do().UnmarshalInto(&p); err != nil {
		return nil, fmt.Errorf("failed to discover OIDC configuration: %v", err)
	}

	if !skipIssuerVerification && p.Issuer != issuerURL {
		return nil, fmt.Errorf("oidc: issuer did not match the issuer returned by provider, expected %q got %q", issuerURL, p.Issuer)
	}

	return &discoveryProvider{
		authURL:              p.AuthURL,
		tokenURL:             p.TokenURL,
		jwksURL:              p.JWKsURL,
		userInfoURL:          p.UserInfoURL,
		codeChallengeAlgs:    p.CodeChallengeAlgs,
		supportedSigningAlgs: p.SupportedSigningAlgs,
	}, nil
}

// discoveryProvider holds the discovered endpoints
type discoveryProvider struct {
	authURL              string
	tokenURL             string
	jwksURL              string
	userInfoURL          string
	codeChallengeAlgs    []string
	supportedSigningAlgs []string
}

// Endpoints returns the discovered endpoints needed for an authentication provider.
func (p *discoveryProvider) Endpoints() Endpoints {
	return Endpoints{
		AuthURL:     p.authURL,
		TokenURL:    p.tokenURL,
		JWKsURL:     p.jwksURL,
		UserInfoURL: p.userInfoURL,
	}
}

// PKCE returns information related to the PKCE (code challenge) support of the provider.
func (p *discoveryProvider) PKCE() PKCE {
	return PKCE{
		CodeChallengeAlgs: p.codeChallengeAlgs,
	}
}

// SupportedSigningAlgs returns the discovered provider signing algorithms.
func (p *discoveryProvider) SupportedSigningAlgs() []string {
	return p.supportedSigningAlgs
}
