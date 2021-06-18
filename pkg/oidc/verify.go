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

	if isValidAudience, err := v.isValidAudience(claims); !isValidAudience {
		return nil, err
	}

	// maybye other additional validation/verification for future purposes...

	return token, err
}

func (v *IDTokenVerifier) isValidAudience(claims map[string]interface{}) (bool, error) {
	if v.AudienceClaim == "" {
		return false, fmt.Errorf("invalid audience claim, oidc-audience-claim  is empty")
	}
	allowedAudiences := append([]string{v.ClientID}, v.IDTokenVerificationOptions.ExtraAudiences...)
	if audienceClaimValue, audienceClaimExists := claims[v.AudienceClaim]; audienceClaimExists {
		logger.Printf("verifying provided aud claim %s with value %s against allowed audiences %v",
			v.AudienceClaim, audienceClaimValue, allowedAudiences)
		for _, allowedAudience := range allowedAudiences {
			if audienceClaimValue == allowedAudience {
				return true, nil
			}
		}
		return false, fmt.Errorf("audience from claim %s with value %s does not match with any of allowed audiences %v",
			v.AudienceClaim, audienceClaimValue, allowedAudiences)
	} else {
		if v.AudienceClaim == "aud" {
			return false, fmt.Errorf("no valid aud claim exists in token")
		}
		logger.Printf("aud claim %s does not exist", v.AudienceClaim)
		if defaultAudienceValue, defaultAudienceExists := claims["aud"]; defaultAudienceExists {
			logger.Printf("falling back to aud claim, as %s claim does not exists", v.AudienceClaim)
			for _, allowedAudience := range allowedAudiences {
				if defaultAudienceValue == allowedAudience {
					return true, nil
				}
			}
			return false, fmt.Errorf("aud with value %s does not match with any of allowed audiences %v",
				defaultAudienceValue, allowedAudiences)
		}
	}
	return false, fmt.Errorf("error validating audience from claim %s against any of %v; claims: %v",
		v.AudienceClaim, allowedAudiences, claims)
}
