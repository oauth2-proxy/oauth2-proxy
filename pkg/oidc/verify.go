package oidc

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
)

// IDTokenVerifier Used to verify an ID Token and extends oidc.IDTokenVerifier from the underlying oidc library
type IDTokenVerifier struct {
	*oidc.IDTokenVerifier
	*IDTokenVerificationOptions
	allowedAudiences map[string]struct{}
}

// IDTokenVerificationOptions options for the oidc.IDTokenVerifier that are required to verify an ID Token
type IDTokenVerificationOptions struct {
	AudienceClaim  string
	ClientID       string
	ExtraAudiences []string
}

// NewVerifier constructs a new IDTokenVerifier
func NewVerifier(iv *oidc.IDTokenVerifier, vo *IDTokenVerificationOptions) *IDTokenVerifier {
	allowedAudiences := make(map[string]struct{})
	allowedAudiences[vo.ClientID] = struct{}{}
	for _, extraAudience := range vo.ExtraAudiences {
		allowedAudiences[extraAudience] = struct{}{}
	}
	return &IDTokenVerifier{iv, vo, allowedAudiences}
}

// Verify verifies incoming ID Token
func (v *IDTokenVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	token, err := v.IDTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %v", err)
	}

	claims := map[string]interface{}{}
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse default id_token claims: %v", err)
	}

	if isValidAudience, err := v.verifyAudience(token, claims); !isValidAudience {
		return nil, err
	}

	return token, err
}

func (v *IDTokenVerifier) verifyAudience(token *oidc.IDToken, claims map[string]interface{}) (bool, error) {
	if audienceClaimValue, audienceClaimExists := claims[v.AudienceClaim]; audienceClaimExists {
		token.Audience = []string{audienceClaimValue.(string)}
		return v.isValidAudience(audienceClaimValue.(string), v.allowedAudiences)
	}
	return false, fmt.Errorf("audience claim %s does not exist in claims: %v",
		v.AudienceClaim, claims)
}

func (v *IDTokenVerifier) isValidAudience(audience string, allowedAudiences map[string]struct{}) (bool, error) {
	if _, allowedAudienceExists := allowedAudiences[audience]; allowedAudienceExists {
		return true, nil
	}
	return false, fmt.Errorf(
		"audience from claim %s with value %s does not match with any of allowed audiences %v",
		v.AudienceClaim, audience, allowedAudiences)
}
