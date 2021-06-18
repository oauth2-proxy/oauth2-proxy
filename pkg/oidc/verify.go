package oidc

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

type IDTokenVerifier struct {
	*oidc.IDTokenVerifier
	*IDTokenVerificationOptions
}

type IDTokenVerificationOptions struct {
	AudienceClaim  string
	ClientID       string
	ExtraAudiences []string
}

func NewVerifier(iv *oidc.IDTokenVerifier, vo *IDTokenVerificationOptions) *IDTokenVerifier {
	return &IDTokenVerifier{iv, vo}
}

func (v *IDTokenVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	token, err := v.IDTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse default id_token claims: %v", err)
	}

	claims := map[string]interface{}{}
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse default id_token claims: %v", err)
	}

	if isValidAudience, err := v.verifyAudience(claims); !isValidAudience {
		return nil, err
	}

	// maybye other additional validation/verification for future purposes...

	return token, err
}

func (v *IDTokenVerifier) verifyAudience(claims map[string]interface{}) (bool, error) {
	allowedAudiences := append([]string{v.ClientID}, v.IDTokenVerificationOptions.ExtraAudiences...)
	if audienceClaimValue, audienceClaimExists := claims[v.AudienceClaim]; audienceClaimExists {
		logger.Printf("verifying provided aud claim %s with value %s against allowed audiences %v",
			v.AudienceClaim, audienceClaimValue, allowedAudiences)
		return v.isValidAudience(audienceClaimValue.(string), allowedAudiences)
	} else {
		if v.AudienceClaim == "aud" {
			return false, fmt.Errorf("no valid aud claim exists in token")
		}
		if defaultAudienceValue, defaultAudienceExists := claims["aud"]; defaultAudienceExists {
			logger.Printf("falling back to aud claim, as %s claim does not exists", v.AudienceClaim)
			return v.isValidAudience(defaultAudienceValue.(string), allowedAudiences)
		} else {
			logger.Printf("aud claim %s does not exist", v.AudienceClaim)
		}
	}
	return false, fmt.Errorf("error validating audience from claim %s against any of %v; claims: %v",
		v.AudienceClaim, allowedAudiences, claims)
}

func (v *IDTokenVerifier) isValidAudience(audience string, allowedAudiences []string) (bool, error) {
	for _, allowedAudience := range allowedAudiences {
		if audience == allowedAudience {
			return true, nil
		}
	}
	return false, fmt.Errorf("aud with value %s does not match with any of allowed audiences %v",
		audience, allowedAudiences)
}
