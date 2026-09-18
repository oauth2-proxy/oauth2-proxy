package middleware

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
)

// defaultGroupsClaim is the token claim used to populate a session's Groups
// when no groups claim name is configured.
const defaultGroupsClaim = "groups"

// TokenToSessionFunc takes a raw ID Token and converts it into a SessionState.
type TokenToSessionFunc func(ctx context.Context, token string) (*sessionsapi.SessionState, error)

// VerifyFunc takes a raw bearer token and verifies it returning the converted
// oidc.IDToken representation of the token.
type VerifyFunc func(ctx context.Context, token string) (*oidc.IDToken, error)

// CreateTokenToSessionFunc provides a handler that is a default implementation
// for converting a JWT into a session.
//
// groupsClaim controls which token claim is used to populate the session's
// Groups. This mirrors the primary OIDC provider's --oidc-groups-claim so that
// bearer tokens verified through this path (e.g. --extra-jwt-issuers) resolve
// groups from the same claim. When empty it defaults to "groups".
func CreateTokenToSessionFunc(verify VerifyFunc, groupsClaim string) TokenToSessionFunc {
	if groupsClaim == "" {
		groupsClaim = defaultGroupsClaim
	}
	return func(ctx context.Context, token string) (*sessionsapi.SessionState, error) {
		var claims struct {
			Subject           string `json:"sub"`
			Email             string `json:"email"`
			Verified          *bool  `json:"email_verified"`
			PreferredUsername string `json:"preferred_username"`
		}

		idToken, err := verify(ctx, token)
		if err != nil {
			return nil, err
		}

		if err := idToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse bearer token claims: %v", err)
		}

		groups, err := extractGroups(idToken, groupsClaim)
		if err != nil {
			return nil, err
		}

		if claims.Email == "" {
			claims.Email = claims.Subject
		}

		// Ensure email is verified
		// If the email is not verified, return an error
		// If the email_verified claim is missing, assume it is verified
		if !ptr.Deref(claims.Verified, true) {
			return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
		}

		newSession := &sessionsapi.SessionState{
			Email:             claims.Email,
			User:              claims.Subject,
			Groups:            groups,
			PreferredUsername: claims.PreferredUsername,
			AccessToken:       token,
			IDToken:           token,
			RefreshToken:      "",
			ExpiresOn:         &idToken.Expiry,
		}

		return newSession, nil
	}
}

// extractGroups reads the configured groups claim from the token. The claim may
// be encoded either as an array of strings or as a single string. A missing
// claim yields no groups, while a claim present in any other format is reported
// as an error so that a misconfigured issuer or groups claim name cannot be
// mistaken for a user that belongs to no groups.
func extractGroups(idToken *oidc.IDToken, groupsClaim string) ([]string, error) {
	var rawClaims map[string]json.RawMessage
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("failed to parse bearer token claims: %v", err)
	}

	raw, ok := rawClaims[groupsClaim]
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
