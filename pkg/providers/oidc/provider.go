package oidc

import (
	"context"
	"fmt"
	"time"
)

// providerJSON represents the information we need from an OIDC discovery
type ProviderJSON struct {
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
func NewProvider(ctx context.Context, issuerURL string, skipIssuerVerification bool, providerJson ProviderJSON) (DiscoveryProvider, error) {
	// go-oidc doesn't let us pass bypass the issuer check this in the oidc.NewProvider call
	// (which uses discovery to get the URLs), so we'll do a quick check ourselves and if
	// we get the URLs, we'll just use the non-discovery path.

	fmt.Printf("Performing OIDC Discovery...")

	if !skipIssuerVerification && providerJson.Issuer != issuerURL {
		return nil, fmt.Errorf("oidc: issuer did not match the issuer returned by provider, expected %q got %q", issuerURL, providerJson.Issuer)
	}
	return &discoveryProvider{
		authURL:              providerJson.AuthURL,
		tokenURL:             providerJson.TokenURL,
		jwksURL:              providerJson.JWKsURL,
		userInfoURL:          providerJson.UserInfoURL,
		codeChallengeAlgs:    providerJson.CodeChallengeAlgs,
		supportedSigningAlgs: providerJson.SupportedSigningAlgs,
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

// IDToken is an OpenID Connect extension that provides a predictable representation
// of an authorization event.
//
// The ID Token only holds fields OpenID Connect requires. To access additional
// claims returned by the server, use the Claims method.
type IDToken struct {
	// The URL of the server which issued this token. OpenID Connect
	// requires this value always be identical to the URL used for
	// initial discovery.
	//
	// Note: Because of a known issue with Google Accounts' implementation
	// this value may differ when using Google.
	//
	// See: https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
	Issuer string

	// The client ID, or set of client IDs, that this token is issued for. For
	// common uses, this is the client that initialized the auth flow.
	//
	// This package ensures the audience contains an expected value.
	Audience []string

	// A unique string which identifies the end user.
	Subject string

	// Expiry of the token. Ths package will not process tokens that have
	// expired unless that validation is explicitly turned off.
	Expiry time.Time
	// When the token was issued by the provider.
	IssuedAt time.Time

	// Initial nonce provided during the authentication redirect.
	//
	// This package does NOT provided verification on the value of this field
	// and it's the user's responsibility to ensure it contains a valid value.
	Nonce string

	// at_hash claim, if set in the ID token. Callers can verify an access token
	// that corresponds to the ID token using the VerifyAccessToken method.
	AccessTokenHash string

	// signature algorithm used for ID token, needed to compute a verification hash of an
	// access token
	sigAlgorithm string

	// Raw payload of the id_token.
	claims []byte

	// Map of distributed claim names to claim sources
	distributedClaims map[string]claimSource
}

type claimSource struct {
	Endpoint    string `json:"endpoint"`
	AccessToken string `json:"access_token"`
}
