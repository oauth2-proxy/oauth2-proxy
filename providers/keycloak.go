package providers

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
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

type keycloakUserInfo struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

func (p *KeycloakProvider) getUserInfo(ctx context.Context, s *sessions.SessionState) (*keycloakUserInfo, error) {
	var userInfo keycloakUserInfo
	err := requests.New(p.ValidateURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalInto(&userInfo)
	if err != nil {
		logger.Errorf("failed making request %s", err)
		return nil, fmt.Errorf("error getting user info: %v", err)
	}
	return &userInfo, nil
}

func getClientRoles(resourceAccess map[string]interface{}) ([]string, error) {
	var clientRoles []string
	for name, list := range resourceAccess {
		scopes, ok := list.(map[string]interface{})
		if !ok {
			return nil, errors.New("error parsing client roles from claims")
		}
		if roles, found := scopes["roles"]; found {
			for _, r := range roles.([]interface{}) {
				clientRoles = append(clientRoles, fmt.Sprintf("%s:%s", name, r))
			}
		}
	}
	return clientRoles, nil
}

type realmAccess struct {
	Roles []string `json:"roles"`
}

type customClaims struct {
	RealmAccess    realmAccess            `json:"realm_access"`
	ResourceAccess map[string]interface{} `json:"resource_access"`
}

func (p *KeycloakProvider) getRoles(s *sessions.SessionState) ([]string, error) {
	// Decode JWT token without verifying the signature
	token, err := jwt.ParseSigned(s.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}
	standardClaims := jwt.Claims{}
	customClaims := customClaims{}
	// Parse claims
	if err := token.UnsafeClaimsWithoutVerification(&standardClaims, &customClaims); err != nil {
		logger.Printf("failed to parse claims: %s", err)
	}
	clientRoles, err := getClientRoles(customClaims.ResourceAccess)
	if err != nil {
		logger.Printf("failed to extract client roles: %s", err)
	}
	return append(customClaims.RealmAccess.Roles, clientRoles...), nil
}

func (p *KeycloakProvider) addGroupsToSession(s *sessions.SessionState, groups []string) error {
	for _, group := range groups {
		s.Groups = append(s.Groups, fmt.Sprintf("group:%s", group))
	}
	return nil
}

func (p *KeycloakProvider) addRolesToSession(s *sessions.SessionState) error {
	roles, err := p.getRoles(s)
	if err != nil {
		return err
	}
	for _, role := range roles {
		s.Groups = append(s.Groups, fmt.Sprintf("role:%s", role))
	}
	return nil
}

func (p *KeycloakProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	userInfo, err := p.getUserInfo(ctx, s)
	if err != nil {
		return err
	}

	s.Email = userInfo.Email

	if p.Group != "" {
		err := p.addGroupsToSession(s, userInfo.Groups)
		if err != nil {
			return err
		}
	}

	if len(p.Roles) > 0 {
		err := p.addRolesToSession(s)
		if err != nil {
			return err
		}
	}

	return nil
}

// PrefixAllowedGroups returns a list of allowed groups, prefixed by their `kind` value
func (p *KeycloakProvider) PrefixAllowedGroups() (groups []string) {

	if p.Group != "" {
		groups = append(groups, fmt.Sprintf("group:%s", p.Group))
	}

	for _, role := range p.Roles {
		groups = append(groups, fmt.Sprintf("role:%s", role))
	}

	return groups
}
