package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"github.com/bitly/go-simplejson"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

// AzureProvider represents an Azure based Identity Provider
type AzureProvider struct {
	*ProviderData
	Tenant          string
	PermittedGroups map[string]string
	ExemptedUsers   map[string]string
}

// NewAzureProvider initiates a new AzureProvider
func NewAzureProvider(p *ProviderData) *AzureProvider {
	p.ProviderName = "Azure"

	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   "graph.microsoft.com",
			Path:   "/v1.0/me",
		}
	}
	if p.ProtectedResource == nil || p.ProtectedResource.String() == "" {
		p.ProtectedResource = &url.URL{
			Scheme: "https",
			Host:   "graph.microsoft.com",
		}
	}
	if p.Scope == "" {
		p.Scope = "openid"
	}

	if p.ApprovalPrompt == "force" {
		p.ApprovalPrompt = "consent"
	}
	return &AzureProvider{ProviderData: p}
}

// Configure defaults the AzureProvider configuration options
func (p *AzureProvider) Configure(tenant string) {
	p.Tenant = tenant
	if tenant == "" {
		p.Tenant = "common"
	}

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/authorize"}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/token",
		}
	}
}

func getAzureHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	// First try to return `userPrincipalName`
	// if not defined, try to return `mail`
	// if that also failed, try to get first record from `otherMails`
	// TODO: Return everything in list and then try requests one by one

	var email string
	var err error

	email, err = json.Get("userPrincipalName").String()
	if err == nil {
		return email, err
	}

	email, err = json.Get("mail").String()

	if err != nil || email == "" {
		otherMails, otherMailsErr := json.Get("otherMails").Array()
		if len(otherMails) > 0 {
			email = otherMails[0].(string)
			err = otherMailsErr
		}
	}

	return email, err
}

func getUserIDFromJSON(json *simplejson.Json) (string, error) {
	// Try to get user ID
	// if not defined, return empty string

	uid, err := json.Get("id").String()
	if err != nil {
		return "", err
	}
	return uid, err
}

func (p *AzureProvider) GetUserDetails(s *sessions.SessionState) (*UserDetails, error) {
	var err error

	if s.AccessToken == "" {
		return nil, errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header = getAzureHeader(s.AccessToken)

	json, err := requests.Request(req)
	if err != nil {
		return nil, err
	}

	email, err := getEmailFromJSON(json)
	if err != nil {
		return nil, err
	}

	uid, _ := getUserIDFromJSON(json)

	if email == "" {
		return nil, errors.New("Client email not found")
	}
	return &UserDetails{
		Email: email,
		UID:   uid,
	}, nil
}

// Get list of groups user belong to. Filter the desired names of groups (in case of huge group set)
func (p *AzureProvider) GetGroups(s *sessions.SessionState, f string) (map[string]string, error) {
	// Azure App Registration requires setting groupMembershipClaims to include group membership in identity token
	// This option is available through ARM template only.
	// For details refer to: https://docs.microsoft.com/pl-pl/azure/active-directory/develop/reference-app-manifest
	if s.IDToken == "" {
		return map[string]string{}, errors.New("missing id token")
	}

	type GroupClaims struct {
		Groups []string `json:"groups"`
		jwt.StandardClaims
	}

	claims := &GroupClaims{}
	jwt.ParseWithClaims(s.IDToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("empty"), nil
	})

	groupsMap := make(map[string]string)
	for _, s := range claims.Groups {
		groupsMap[s] = s
	}
	return groupsMap, nil
}

func (p *AzureProvider) GetLoginURL(redirectURI, state string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "id_token code")
	params.Set("redirect_uri", redirectURI)
	params.Set("response_mode", "form_post")
	params.Add("scope", p.Scope)
	params.Add("state", state)
	params.Set("prompt", p.ApprovalPrompt)
	params.Set("nonce", randSeq(32))
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}
	a.RawQuery = params.Encode()

	return a.String()
}

func (p *AzureProvider) SetGroupRestriction(groups []string) {
	// Get list of groups (optionally with Group IDs) that ONLY allowed for user
	// That means even if user has wider group membership, only membership in those groups will be forwarded

	p.PermittedGroups = make(map[string]string)
	if len(groups) == 0 {
		return
	}
	for _, pGroup := range groups {
		splittedGroup := strings.Split(pGroup, ":")
		if len(splittedGroup) == 1 {
			p.PermittedGroups[splittedGroup[0]] = ""
		} else if len(splittedGroup) == 2 {
			p.PermittedGroups[splittedGroup[0]] = splittedGroup[1]
		} else {
			logger.Printf("Warning: failed to parse '%v'. Too many ':' separators", pGroup)
		}
	}
}

func (p *AzureProvider) SetGroupsExemption(exemptions []string) {
	// Get list of users (optionally with User IDs) that could still be allowed to login
	// when group membership calls fail (e.g. insufficient permissions)

	p.ExemptedUsers = make(map[string]string)
	if len(exemptions) == 0 {
		return
	}

	var userRecord string
	var groupName string
	for _, pRecord := range exemptions {
		splittedRecord := strings.Split(pRecord, ":")

		if len(splittedRecord) == 1 {
			userRecord, groupName = splittedRecord[0], ""
		} else if len(splittedRecord) == 2 {
			userRecord, groupName = splittedRecord[0], splittedRecord[1]
		} else {
			userRecord = splittedRecord[0] + ":" + splittedRecord[1]
			groupName = splittedRecord[2]
		}
		p.ExemptedUsers[userRecord] = groupName
	}
}

func (p *AzureProvider) ValidateGroupWithSession(s *sessions.SessionState) bool {
	if len(p.PermittedGroups) == 0 {
		return true
	}
	for _, group := range s.Groups {
		for _, groupID := range p.PermittedGroups {
			if strings.Contains(group, groupID) {
				return true
			}
		}
	}
	return false
}
