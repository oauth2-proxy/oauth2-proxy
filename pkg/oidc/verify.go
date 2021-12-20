package oidc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/coreos/go-oidc/v3/oidc"
)

// IDTokenVerifier Used to verify an ID Token and extends oidc.IDTokenVerifier from the underlying oidc library
type IDTokenVerifier struct {
	*oidc.IDTokenVerifier
	*IDTokenVerificationOptions
	allowedAudiences map[string]struct{}
}

// IDTokenVerificationOptions options for the oidc.IDTokenVerifier that are required to verify an ID Token
type IDTokenVerificationOptions struct {
	AudienceClaims []string
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
	for _, audienceClaim := range v.AudienceClaims {
		if audienceClaimValue, audienceClaimExists := claims[audienceClaim]; audienceClaimExists {

			// audience claim value can be either interface{} or []interface{},
			// as per spec `aud` can be either a string or a list of strings
			switch audienceClaimValueType := audienceClaimValue.(type) {
			case []interface{}:
				token.Audience = v.interfaceSliceToString(audienceClaimValue)
			case interface{}:
				token.Audience = []string{audienceClaimValue.(string)}
			default:
				return false, fmt.Errorf("audience claim %s holds unsupported type %T",
					audienceClaim, audienceClaimValueType)
			}

			return v.isValidAudience(audienceClaim, token.Audience, v.allowedAudiences)
		}
	}

	return false, fmt.Errorf("audience claims %v do not exist in claims: %v",
		v.AudienceClaims, claims)
}

func (v *IDTokenVerifier) isValidAudience(claim string, audience []string, allowedAudiences map[string]struct{}) (bool, error) {
	for _, aud := range audience {
		if _, allowedAudienceExists := allowedAudiences[aud]; allowedAudienceExists {
			return true, nil
		}
	}

	return false, fmt.Errorf(
		"audience from claim %s with value %s does not match with any of allowed audiences %v",
		claim, audience, allowedAudiences)
}

func (v *IDTokenVerifier) interfaceSliceToString(slice interface{}) []string {
	s := reflect.ValueOf(slice)
	if s.Kind() != reflect.Slice {
		panic(fmt.Sprintf("given a non-slice type %s", s.Kind()))
	}
	var strings []string
	for i := 0; i < s.Len(); i++ {
		strings = append(strings, s.Index(i).Interface().(string))
	}
	return strings
}
