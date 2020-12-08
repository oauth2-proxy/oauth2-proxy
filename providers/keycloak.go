package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
	"gopkg.in/square/go-jose.v2/jwt"
)

type KeycloakProvider struct {
	*ProviderData
	Group string
	Roles []string
}

var _ Provider = (*KeycloakProvider)(nil)

const (
	keycloakProviderName = "Keycloak"
	keycloakDefaultScope = "api"
)

var (
	// Default Login URL for Keycloak.
	// Pre-parsed URL of https://keycloak.org/oauth/authorize.
	keycloakDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "keycloak.org",
		Path:   "/oauth/authorize",
	}

	// Default Redeem URL for Keycloak.
	// Pre-parsed URL of ttps://keycloak.org/oauth/token.
	keycloakDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "keycloak.org",
		Path:   "/oauth/token",
	}

	// Default Validation URL for Keycloak.
	// Pre-parsed URL of https://keycloak.org/api/v3/user.
	keycloakDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "keycloak.org",
		Path:   "/api/v3/user",
	}
)

func NewKeycloakProvider(p *ProviderData) *KeycloakProvider {
	p.setProviderDefaults(providerDefaults{
		name:        keycloakProviderName,
		loginURL:    keycloakDefaultLoginURL,
		redeemURL:   keycloakDefaultRedeemURL,
		profileURL:  nil,
		validateURL: keycloakDefaultValidateURL,
		scope:       keycloakDefaultScope,
	})
	return &KeycloakProvider{ProviderData: p}
}

func (p *KeycloakProvider) SetGroup(group string) {
	p.Group = group
}

func (p *KeycloakProvider) SetRoles(roles []string) {
	p.Roles = roles
}

func ExtractRolesFromClaims(claims map[string]interface{}) []string {
	var roleList []string

	if realmRoles, found := claims["realm_access"].(map[string]interface{}); found {
		if roles, found := realmRoles["roles"]; found {
			for _, r := range roles.([]interface{}) {
				roleList = append(roleList, fmt.Sprintf("%s", r))
			}
		}
	}

	if clientRoles, found := claims["resource_access"].(map[string]interface{}); found {
		for name, list := range clientRoles {
			scopes := list.(map[string]interface{})
			if roles, found := scopes["roles"]; found {
				for _, r := range roles.([]interface{}) {
					roleList = append(roleList, fmt.Sprintf("%s:%s", name, r))
				}
			}
		}
	}

	return roleList
}

func (p *KeycloakProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	json, err := requests.New(p.ValidateURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalJSON()

	if err != nil {
		logger.Errorf("failed making request %s", err)
		return "", err
	}

	if p.Group != "" {
		var groups, err = json.Get("groups").Array()
		if err != nil {
			logger.Printf("groups not found %s", err)
			return "", err
		}

		var found = false
		for i := range groups {
			if groups[i].(string) == p.Group {
				found = true
				break
			}
		}

		if !found {
			logger.Printf("group not found, access denied")
			return "", nil
		}
	}

	if len(p.Roles) > 0 {
		claims := make(map[string]interface{})

		// Decode JWT token without verifying the signature
		token, err := jwt.ParseSigned(s.AccessToken)

		if err != nil {
			logger.Printf("failed to parse token %s", err)
			return "", nil
		}

		// Parse claims
		if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
			logger.Printf("failed to parse claims %s", err)
		}

		var roles = ExtractRolesFromClaims(claims)

		if isSubarray(roles, p.Roles) != true {
			logger.Printf("one or more roles not found, access denied")
			return "", nil
		}
	}

	return json.Get("email").String()
}
