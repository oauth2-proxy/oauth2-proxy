// Copyright (c) 2022 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package go_oidc

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

var (
	errNoAtHash      = errors.New("id token did not have an access token hash")
	errInvalidAtHash = errors.New("access token hash does not match value in ID token")
)

type contextKey int

var issuerURLKey contextKey

// ClientContext returns a new Context that carries the provided HTTP client.
//
// This method sets the same context key used by the golang.org/x/oauth2 package,
// so the returned context works for that package too.
//
//	myClient := &http.Client{}
//	ctx := oidc.ClientContext(parentContext, myClient)
//
//	// This will use the custom client
//	provider, err := oidc.NewProvider(ctx, "https://accounts.example.com")
func ClientContext(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func getClient(ctx context.Context) *http.Client {
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		return c
	}
	return nil
}

// Provider represents an OpenID Connect server's configuration.
type Provider struct {
	issuer        string
	authURL       string
	tokenURL      string
	deviceAuthURL string
	userInfoURL   string
	jwksURL       string
	algorithms    []string

	// Raw claims returned by the server.
	rawClaims []byte

	// Guards all of the following fields.
	mu sync.Mutex
	// HTTP client specified from the initial NewProvider request. This is used
	// when creating the common key set.
	client *http.Client
	// A key set that uses context.Background() and is shared between all code paths
	// that don't have a convinent way of supplying a unique context.
	commonRemoteKeySet KeySet
}

func (p *Provider) remoteKeySet() KeySet {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.commonRemoteKeySet == nil {
		ctx := context.Background()
		if p.client != nil {
			ctx = ClientContext(ctx, p.client)
		}
		p.commonRemoteKeySet = NewRemoteKeySet(ctx, p.jwksURL)
	}
	return p.commonRemoteKeySet
}

// ProviderConfig allows creating providers when discovery isn't supported. It's
// generally easier to use NewProvider directly.
type ProviderConfig struct {
	// IssuerURL is the identity of the provider, and the string it uses to sign
	// ID tokens with. For example "https://accounts.google.com". This value MUST
	// match ID tokens exactly.
	IssuerURL string
	// AuthURL is the endpoint used by the provider to support the OAuth 2.0
	// authorization endpoint.
	AuthURL string
	// TokenURL is the endpoint used by the provider to support the OAuth 2.0
	// token endpoint.
	TokenURL string
	// DeviceAuthURL is the endpoint used by the provider to support the OAuth 2.0
	// device authorization endpoint.
	DeviceAuthURL string
	// UserInfoURL is the endpoint used by the provider to support the OpenID
	// Connect UserInfo flow.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	UserInfoURL string
	// JWKSURL is the endpoint used by the provider to advertise public keys to
	// verify issued ID tokens. This endpoint is polled as new keys are made
	// available.
	JWKSURL string

	// Algorithms, if provided, indicate a list of JWT algorithms allowed to sign
	// ID tokens. If not provided, this defaults to the algorithms advertised by
	// the JWK endpoint, then the set of algorithms supported by this package.
	Algorithms []string
}

// NewProvider initializes a provider from a set of endpoints, rather than
// through discovery.
func (p *ProviderConfig) NewProvider(ctx context.Context) *Provider {
	return &Provider{
		issuer:        p.IssuerURL,
		authURL:       p.AuthURL,
		tokenURL:      p.TokenURL,
		deviceAuthURL: p.DeviceAuthURL,
		userInfoURL:   p.UserInfoURL,
		jwksURL:       p.JWKSURL,
		algorithms:    p.Algorithms,
		client:        getClient(ctx),
	}
}

// Claims unmarshals raw fields returned by the server during discovery.
//
//	var claims struct {
//	    ScopesSupported []string `json:"scopes_supported"`
//	    ClaimsSupported []string `json:"claims_supported"`
//	}
//
//	if err := provider.Claims(&claims); err != nil {
//	    // handle unmarshaling error
//	}
//
// For a list of fields defined by the OpenID Connect spec see:
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (p *Provider) Claims(v interface{}) error {
	if p.rawClaims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(p.rawClaims, v)
}

// Endpoint returns the OAuth2 auth and token endpoints for the given provider.
func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{AuthURL: p.authURL, DeviceAuthURL: p.deviceAuthURL, TokenURL: p.tokenURL}
}

// UserInfoEndpoint returns the OpenID Connect userinfo endpoint for the given
// provider.
func (p *Provider) UserInfoEndpoint() string {
	return p.userInfoURL
}

// UserInfo represents the OpenID Connect userinfo claims.
type UserInfo struct {
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	claims []byte
}

// Claims unmarshals the raw JSON object claims into the provided object.
func (u *UserInfo) Claims(v interface{}) error {
	if u.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(u.claims, v)
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

// Claims unmarshals the raw JSON payload of the ID Token into a provided struct.
//
//	idToken, err := idTokenVerifier.Verify(rawIDToken)
//	if err != nil {
//		// handle error
//	}
//	var claims struct {
//		Email         string `json:"email"`
//		EmailVerified bool   `json:"email_verified"`
//	}
//	if err := idToken.Claims(&claims); err != nil {
//		// handle error
//	}
func (i *IDToken) Claims(v interface{}) error {
	if i.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(i.claims, v)
}

// VerifyAccessToken verifies that the hash of the access token that corresponds to the iD token
// matches the hash in the id token. It returns an error if the hashes  don't match.
// It is the caller's responsibility to ensure that the optional access token hash is present for the ID token
// before calling this method. See https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
func (i *IDToken) VerifyAccessToken(accessToken string) error {
	if i.AccessTokenHash == "" {
		return errNoAtHash
	}
	var h hash.Hash
	switch i.sigAlgorithm {
	case RS256, ES256, PS256:
		h = sha256.New()
	case RS384, ES384, PS384:
		h = sha512.New384()
	case RS512, ES512, PS512, EdDSA:
		h = sha512.New()
	default:
		return fmt.Errorf("oidc: unsupported signing algorithm %q", i.sigAlgorithm)
	}
	h.Write([]byte(accessToken)) // hash documents that Write will never return an error
	sum := h.Sum(nil)[:h.Size()/2]
	actual := base64.RawURLEncoding.EncodeToString(sum)
	if actual != i.AccessTokenHash {
		return errInvalidAtHash
	}
	return nil
}

type idToken struct {
	Issuer       string                 `json:"iss"`
	Subject      string                 `json:"sub"`
	Audience     audience               `json:"aud"`
	Expiry       jsonTime               `json:"exp"`
	IssuedAt     jsonTime               `json:"iat"`
	NotBefore    *jsonTime              `json:"nbf"`
	Nonce        string                 `json:"nonce"`
	AtHash       string                 `json:"at_hash"`
	ClaimNames   map[string]string      `json:"_claim_names"`
	ClaimSources map[string]claimSource `json:"_claim_sources"`
}

type claimSource struct {
	Endpoint    string `json:"endpoint"`
	AccessToken string `json:"access_token"`
}

type stringAsBool bool

func (sb *stringAsBool) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case "true", `"true"`:
		*sb = true
	case "false", `"false"`:
		*sb = false
	default:
		return errors.New("invalid value for boolean")
	}
	return nil
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var auds []string
	if err := json.Unmarshal(b, &auds); err != nil {
		return err
	}
	*a = auds
	return nil
}

type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}
