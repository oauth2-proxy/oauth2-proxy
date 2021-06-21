package oidc

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// IDTokenVerifier Used to verify an ID Token and extends oidc.IDTokenVerifier from the underlying oidc library
type IDTokenVerifier struct {
	*oidc.IDTokenVerifier
	*IDTokenVerificationOptions
	allowedAudiences []string
}

// IDTokenVerificationOptions options for the oidc.IDTokenVerifier that are required to verify an ID Token
type IDTokenVerificationOptions struct {
	AudienceClaim  string
	ClientID       string
	ExtraAudiences []string
}

// NewVerifier constructs a new IDTokenVerifier
func NewVerifier(iv *oidc.IDTokenVerifier, vo *IDTokenVerificationOptions) *IDTokenVerifier {
	allowedAudiences := append([]string{vo.ClientID}, vo.ExtraAudiences...)
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

	if isValidAudience, err := v.verifyAudience(claims); !isValidAudience {
		return nil, err
	}

	// maybe other additional validation/verification for future purposes...

	return token, err
}

func (v *IDTokenVerifier) verifyAudience(claims map[string]interface{}) (bool, error) {
	if audienceClaimValue, audienceClaimExists := claims[v.AudienceClaim]; audienceClaimExists {
		logger.Printf("verifying provided audience claim %s with value %s against allowed audiences %v",
			v.AudienceClaim, audienceClaimValue, v.allowedAudiences)
		return v.isValidAudience(audienceClaimValue.(string), v.allowedAudiences)
	}
	return false, fmt.Errorf("audience claim %s does not exist in claims: %v",
		v.AudienceClaim, v.allowedAudiences)
}

func (v *IDTokenVerifier) isValidAudience(audience string, allowedAudiences []string) (bool, error) {
	for _, allowedAudience := range allowedAudiences {
		if audience == allowedAudience {
			return true, nil
		}
	}
	return false, fmt.Errorf(
		"audience from claim %s with value %s does not match with any of allowed audiences %v",
		v.AudienceClaim, audience, allowedAudiences)
}
