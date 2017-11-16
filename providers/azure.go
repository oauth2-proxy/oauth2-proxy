package providers

import (
	"errors"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/bitly/oauth2_proxy/api"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type AzureProvider struct {
	*ProviderData
	Tenant          string
	PermittedGroups []string
}

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
	log.Printf("Approval prompt: '%s'", p.ApprovalPrompt)

	return &AzureProvider{ProviderData: p}
}

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

func getAzureHeader(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	var email string
	var err error

	email, err = json.Get("mail").String()

	if err != nil || email == "" {
		otherMails, otherMailsErr := json.Get("otherMails").Array()
		if len(otherMails) > 0 {
			email = otherMails[0].(string)
		}
		err = otherMailsErr
	}

	return email, err
}

func (p *AzureProvider) GetEmailAddress(s *SessionState) (string, error) {
	var email string
	var err error

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAzureHeader(s.AccessToken)

	json, err := api.Request(req)

	if err != nil {
		return "", err
	}

	email, err = getEmailFromJSON(json)

	if err == nil && email != "" {
		return email, err
	}

	email, err = json.Get("userPrincipalName").String()

	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}

	if email == "" {
		log.Printf("failed to get email address")
		return "", err
	}

	return email, err
}

// Get list of groups user belong to. Filter the desired names of groups (in case of huge group set)
func (p *AzureProvider) GetGroups(s *SessionState, f string) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	if s.IDToken == "" {
		return "", errors.New("missing id token")
	}

	// For future use. Right now microsoft graph don't support filter
	// http://docs.oasis-open.org/odata/odata/v4.0/errata02/os/complete/part2-url-conventions/odata-v4.0-errata02-os-part2-url-conventions-complete.html#_Toc406398116

	/*
		var request string = "https://graph.microsoft.com/v1.0/me/memberOf?$select=id,displayName,groupTypes,securityEnabled,description,mailEnabled&$top=999"
		if f != "" {
			request += "?$filter=contains(displayName, '"+f+"')"
		}
	*/
	//
	// Filters that will be possible to use:
	// contains - unknown function | "https://graph.microsoft.com/v1.0/me/memberOf?$filter=contains(displayName,%27groupname%27)"
	// startswith - not supported  | "https://graph.microsoft.com/v1.0/me/memberOf?$filter=startswith(displayName,%27groupname%27)"
	// substring - not supported   | "https://graph.microsoft.com/v1.0/me/memberOf?$filter=substring(displayName,0,2)%20eq%20%27groupname%27"

	requestUrl := "https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName"
	workaround_set := false

	groups := make([]string, 0)

	for {
		req, err := http.NewRequest("GET", requestUrl, nil)
		// err = errors.New("fake error")

		if err != nil {
            return "", err
		}
		req.Header = getAzureHeader(s.AccessToken)
		req.Header.Add("Content-Type", "application/json")

		groupData, err := api.Request(req)
		if err != nil {
            // If workaround already tried, just fail the execution
            if workaround_set {
           	    log.Printf("[GetGroups] We tried hard, but still receive error: '%s'", err)
                return "", err
            }

		    // It might be that it is a Graph bug, try to workaround it by accessing another URL
		    log.Printf("[GetGroups] Failed to get groups details: %s", err)
            requestUrl = "https://graph.microsoft.com/v1.0/users/" + s.Email + "/memberOf"
		    log.Printf("[GetGroups] Try to workaround by accessing: '%s'", requestUrl)
            workaround_set = true
            continue
		}

		for _, groupInfo := range groupData.Get("value").MustArray() {
			v, ok := groupInfo.(map[string]interface{})
			if !ok {
				continue
			}
			dname := v["displayName"].(string)
			if strings.Contains(dname, f) {
				groups = append(groups, dname)
			}

		}

		if nextlink := groupData.Get("@odata.nextLink").MustString(); nextlink != "" {
			requestUrl = nextlink
		} else {
			break
		}
	}

	return strings.Join(groups, "|"), nil
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
	params.Set("nonce", "FIXME")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}
	a.RawQuery = params.Encode()

	return a.String()
}

func (p *AzureProvider) SetGroupRestriction(groups []string) {
	if len(groups) == 1 && strings.Index(groups[0], "|") >= 0 {
		p.PermittedGroups = strings.Split(groups[0], "|")
	} else {
		p.PermittedGroups = groups
	}
	log.Printf("Set group restrictions. Allowed groups are:")
	for _, pGroup := range p.PermittedGroups {
		log.Printf("\t'%s'", pGroup)
	}
}

func (p *AzureProvider) ValidateGroup(s *SessionState) bool {
	if len(p.PermittedGroups) != 0 {
		for _, pGroup := range p.PermittedGroups {
			if strings.Contains(s.Groups, pGroup) {
				return true
			}
		}
		return false
	}
	return true
}
