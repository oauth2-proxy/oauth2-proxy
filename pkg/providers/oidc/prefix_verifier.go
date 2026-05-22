package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// PrefixVerifier dynamically verifies JWT tokens whose issuer matches a configured
// URL prefix. For each unique issuer discovered at runtime, it performs OIDC discovery
// and caches the resulting verifier.
type PrefixVerifier struct {
	prefix         string
	audience       string
	audienceClaims []string
	extraAudiences []string

	mu        sync.RWMutex
	verifiers map[string]IDTokenVerifier
}

// PrefixVerifierOptions configures a PrefixVerifier.
type PrefixVerifierOptions struct {
	// Prefix is the issuer URL prefix to match (e.g. "https://keycloak.example.com/realms/TENANT_")
	Prefix string
	// Audience is the expected audience (client_id)
	Audience string
	// AudienceClaims specifies which claims to check for audience
	AudienceClaims []string
	// ExtraAudiences are additional allowed audiences
	ExtraAudiences []string
}

// NewPrefixVerifier creates a new PrefixVerifier.
func NewPrefixVerifier(opts PrefixVerifierOptions) *PrefixVerifier {
	return &PrefixVerifier{
		prefix:         opts.Prefix,
		audience:       opts.Audience,
		audienceClaims: opts.AudienceClaims,
		extraAudiences: opts.ExtraAudiences,
		verifiers:      make(map[string]IDTokenVerifier),
	}
}

// Verify checks if the token's issuer matches the prefix and verifies it.
func (pv *PrefixVerifier) Verify(ctx context.Context, rawToken string) (*oidc.IDToken, error) {
	issuer, err := extractIssuerFromJWT(rawToken)
	if err != nil {
		return nil, fmt.Errorf("prefix verifier: failed to extract issuer: %w", err)
	}

	if !strings.HasPrefix(issuer, pv.prefix) {
		return nil, fmt.Errorf("prefix verifier: issuer %q does not match prefix %q", issuer, pv.prefix)
	}

	verifier, err := pv.getOrCreateVerifier(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("prefix verifier: failed to get verifier for issuer %q: %w", issuer, err)
	}

	return verifier.Verify(ctx, rawToken)
}

// getOrCreateVerifier retrieves a cached verifier or creates one via OIDC discovery.
func (pv *PrefixVerifier) getOrCreateVerifier(ctx context.Context, issuer string) (IDTokenVerifier, error) {
	// Fast path: check cache with read lock
	pv.mu.RLock()
	v, ok := pv.verifiers[issuer]
	pv.mu.RUnlock()
	if ok {
		return v, nil
	}

	// Slow path: create verifier with write lock (double-checked locking)
	pv.mu.Lock()
	defer pv.mu.Unlock()

	// Re-check after acquiring write lock
	if v, ok := pv.verifiers[issuer]; ok {
		return v, nil
	}

	verifier, err := pv.createVerifier(ctx, issuer)
	if err != nil {
		return nil, err
	}

	pv.verifiers[issuer] = verifier
	return verifier, nil
}

// createVerifier performs OIDC discovery for the given issuer and creates a verifier.
func (pv *PrefixVerifier) createVerifier(ctx context.Context, issuer string) (IDTokenVerifier, error) {
	ctx = oidc.ClientContext(ctx, requests.DefaultHTTPClient)

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		// Fall back to JWKs URL if discovery fails
		jwksURL := strings.TrimSuffix(issuer, "/") + "/.well-known/jwks.json"
		keySet := oidc.NewRemoteKeySet(ctx, jwksURL)
		oidcConfig := &oidc.Config{
			ClientID:          pv.audience,
			SkipIssuerCheck:   false,
			SkipClientIDCheck: true,
		}
		rawVerifier := oidc.NewVerifier(issuer, keySet, oidcConfig)
		return NewVerifier(rawVerifier, IDTokenVerificationOptions{
			AudienceClaims: pv.audienceClaims,
			ClientID:       pv.audience,
			ExtraAudiences: pv.extraAudiences,
		}), nil
	}

	oidcConfig := &oidc.Config{
		ClientID:          pv.audience,
		SkipIssuerCheck:   false,
		SkipClientIDCheck: true,
	}
	rawVerifier := provider.Verifier(oidcConfig)
	return NewVerifier(rawVerifier, IDTokenVerificationOptions{
		AudienceClaims: pv.audienceClaims,
		ClientID:       pv.audience,
		ExtraAudiences: pv.extraAudiences,
	}), nil
}

// extractIssuerFromJWT decodes the payload of a JWT (without verification) to extract the "iss" claim.
func extractIssuerFromJWT(rawToken string) (string, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token has %d parts, expected 3", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to unmarshal JWT claims: %w", err)
	}

	if claims.Issuer == "" {
		return "", fmt.Errorf("JWT has no issuer claim")
	}

	return claims.Issuer, nil
}
