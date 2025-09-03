package oidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// idTokenVerifier allows an ID Token to be verified against the issue and provided keys.
type IDTokenVerifier interface {
	Verify(context.Context, string) (*oidc.IDToken, error)
}

// idTokenVerifier Used to verify an ID Token and extends oidc.idTokenVerifier from the underlying oidc library
type idTokenVerifier struct {
	verifier            *oidc.IDTokenVerifier
	verificationOptions IDTokenVerificationOptions
	allowedAudiences    map[string]struct{}
}

// IDTokenVerificationOptions options for the oidc.idTokenVerifier that are required to verify an ID Token
type IDTokenVerificationOptions struct {
	AudienceClaims []string
	ClientID       string
	ExtraAudiences []string
}

// NewVerifier constructs a new idTokenVerifier
func NewVerifier(iv *oidc.IDTokenVerifier, vo IDTokenVerificationOptions) IDTokenVerifier {
	allowedAudiences := make(map[string]struct{})
	allowedAudiences[vo.ClientID] = struct{}{}
	for _, extraAudience := range vo.ExtraAudiences {
		allowedAudiences[extraAudience] = struct{}{}
	}
	return &idTokenVerifier{
		verifier:            iv,
		verificationOptions: vo,
		allowedAudiences:    allowedAudiences,
	}
}

// Verify verifies incoming ID Token
func (v *idTokenVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	token, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %v", err)
	}

	claims := map[string]interface{}{}
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse default id_token claims: %v", err)
	}

	return token, err
}
