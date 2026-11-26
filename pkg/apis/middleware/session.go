package middleware

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
)

// SessionClaimMapping selects literal token claim names for session fields.
// Empty fields default to sub, email, groups, and preferred_username respectively.
type SessionClaimMapping struct {
	User              string
	Email             string
	Groups            string
	PreferredUsername string
}

// TokenToSessionFunc takes a raw ID Token and converts it into a SessionState.
type TokenToSessionFunc func(ctx context.Context, token string) (*sessionsapi.SessionState, error)

// VerifyFunc takes a raw bearer token and verifies it returning the converted
// oidc.IDToken representation of the token.
type VerifyFunc func(ctx context.Context, token string) (*oidc.IDToken, error)

// CreateTokenToSessionFunc provides a handler that is a default implementation
// for converting a JWT into a session.
func CreateTokenToSessionFunc(verify VerifyFunc, mapping SessionClaimMapping) TokenToSessionFunc {
	mapping.User = cmp.Or(mapping.User, "sub")
	mapping.Email = cmp.Or(mapping.Email, "email")
	mapping.Groups = cmp.Or(mapping.Groups, "groups")
	mapping.PreferredUsername = cmp.Or(mapping.PreferredUsername, "preferred_username")

	return func(ctx context.Context, token string) (*sessionsapi.SessionState, error) {
		idToken, err := verify(ctx, token)
		if err != nil {
			return nil, err
		}

		var claims map[string]json.RawMessage
		if err := idToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse bearer token claims: %v", err)
		}

		newSession := &sessionsapi.SessionState{}
		var verified *bool
		for _, field := range []struct {
			claim string
			dst   any
		}{
			{mapping.User, &newSession.User},
			{mapping.Email, &newSession.Email},
			{mapping.PreferredUsername, &newSession.PreferredUsername},
			{"email_verified", &verified},
		} {
			if raw, ok := claims[field.claim]; ok {
				if err := json.Unmarshal(raw, field.dst); err != nil {
					return nil, fmt.Errorf("failed to parse bearer token claim %q: %w", field.claim, err)
				}
			}
		}

		groups, err := extractGroups(claims, mapping.Groups)
		if err != nil {
			return nil, err
		}

		if newSession.Email == "" {
			newSession.Email = newSession.User
		}

		// Ensure email is verified
		// If the email is not verified, return an error
		// If the email_verified claim is missing, assume it is verified
		if !ptr.Deref(verified, true) {
			return nil, fmt.Errorf("email in id_token (%s) isn't verified", newSession.Email)
		}

		newSession.Groups = groups
		newSession.AccessToken = token
		newSession.IDToken = token
		newSession.ExpiresOn = &idToken.Expiry

		return newSession, nil
	}
}

// extractGroups reads the configured groups claim from the token. The claim may
// be encoded either as an array of strings or as a single string. A missing
// claim yields no groups, while a claim present in any other format is reported
// as an error so that a misconfigured issuer or groups claim name cannot be
// mistaken for a user that belongs to no groups.
func extractGroups(claims map[string]json.RawMessage, groupsClaim string) ([]string, error) {
	raw, ok := claims[groupsClaim]
	if !ok {
		return nil, nil
	}

	var groups []string
	if err := json.Unmarshal(raw, &groups); err == nil {
		return groups, nil
	}

	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}, nil
	}

	return nil, fmt.Errorf("failed to parse groups claim %q: expected a string or an array of strings", groupsClaim)
}
