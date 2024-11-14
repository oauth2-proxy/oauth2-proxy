package oidc

import (
	"context"
	"fmt"
	"reflect"

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
	AudienceClaims       []string
	ClientID             string
	ExtraAudiences       []string
	AllowUnverifiedEmail bool
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

	if hasVerifiedClaims, err := v.verifyClaims(token, claims); !hasVerifiedClaims {
		return nil, err
	}

	return token, err
}

func (v *idTokenVerifier) verifyClaims(token *oidc.IDToken, claims map[string]interface{}) (bool, error) {
	if isValidAudience, err := v.verifyAudience(token, claims); !isValidAudience {
		return false, fmt.Errorf("verifyAudience: %w", err)
	}

	if isVerifiedEmail, err := v.verifyEmail(token); !isVerifiedEmail {
		return false, fmt.Errorf("verifyEmail: %w", err)
	}

	return true, nil
}

func (v *idTokenVerifier) verifyAudience(token *oidc.IDToken, claims map[string]interface{}) (bool, error) {
	for _, audienceClaim := range v.verificationOptions.AudienceClaims {
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
		v.verificationOptions.AudienceClaims, claims)
}

func (v *idTokenVerifier) isValidAudience(claim string, audience []string, allowedAudiences map[string]struct{}) (bool, error) {
	for _, aud := range audience {
		if _, allowedAudienceExists := allowedAudiences[aud]; allowedAudienceExists {
			return true, nil
		}
	}

	return false, fmt.Errorf(
		"audience from claim %s with value %s does not match with any of allowed audiences %v",
		claim, audience, allowedAudiences)
}

func (v *idTokenVerifier) interfaceSliceToString(slice interface{}) []string {
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

func (v *idTokenVerifier) verifyEmail(token *oidc.IDToken) (bool, error) {

	var claims struct {
		Subject  string `json:"sub"`
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}

	if err := token.Claims(&claims); err != nil {
		return false, fmt.Errorf("failed to parse bearer token claims: %w", err)
	}

	if claims.Email == "" {
		claims.Email = claims.Subject
	}

	if claims.Verified != nil && !*claims.Verified && !v.verificationOptions.AllowUnverifiedEmail {
		return false, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	return true, nil
}
