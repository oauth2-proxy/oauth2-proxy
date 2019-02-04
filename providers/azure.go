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
	PermittedGroups map[string]string
	ExemptedUsers   map[string]string
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

func (p *AzureProvider) GetUserDetails(s *SessionState) (map[string]string, error) {
	userDetails := map[string]string{}
	var err error

	if s.AccessToken == "" {
		return userDetails, errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return userDetails, err
	}
	req.Header = getAzureHeader(s.AccessToken)

	json, err := api.Request(req)

	if err != nil {
		return userDetails, err
	}

	log.Printf(" JSON: %v", json)
	for key, value := range json.Interface().(map[string]interface{}) {
		log.Printf("\t %20v : %v", key, value)
	}
	email, err := getEmailFromJSON(json)
	userDetails["email"] = email

	if err != nil {
		log.Printf("[GetEmailAddress] failed making request: %s", err)
		return userDetails, err
	}

	uid, err := getUserIDFromJSON(json)
	userDetails["uid"] = uid
	if err != nil {
		log.Printf("[GetEmailAddress] failed to get User ID: %s", err)
	}

	if email == "" {
		log.Printf("failed to get email address")
		return userDetails, errors.New("Client email not found")
	}
	log.Printf("[GetEmailAddress] Chosen email address: '%s'", email)

	return userDetails, nil
}

// Get list of groups user belong to. Filter the desired names of groups (in case of huge group set)
func (p *AzureProvider) GetGroups(s *SessionState, f string) (map[string]string, error) {
	if s.AccessToken == "" {
		return map[string]string{}, errors.New("missing access token")
	}

	if s.IDToken == "" {
		return map[string]string{}, errors.New("missing id token")
	}

	// Step 1: Try the most simple request that returns all group membership for user
	groups, err := p.GetAllGroupMemberships(s, f)
	if err == nil {
		log.Printf("GetGroups: got list of groups: %v", groups)
		return groups, err
	}

	// Step 2: Ok then, try to check groups from `permit_groups` one by one if they have user in member list
	if len(p.PermittedGroups) != 0 {
		log.Printf("GetGroups: unable to get group membership, will try to get check each group individually: %v", err)
		groups := map[string]string{}
		for gName, gID := range p.PermittedGroups {
			log.Printf("GetGroups: checking membership in: %v", gName)
			found, err := p.HasGroupMembership(s, gName, gID)
			if err != nil {
				log.Printf("GetGroups: checking membership in: %v : failed", gName)
			} else if found {
				groups[gName] = gID
			}
		}
		if len(groups) > 0 {
			log.Printf("GetGroups: returning list of groups that we were able to verify individually: %v", groups)
			return groups, nil
		}
	} else {
		log.Printf("GetGroups: unable to get group membership. We do not have defined `permit_groups` to check them individually: %v", err)
	}

	// Step 3: Well, looks like we have no other option but only check if this user is listed in local `groups_exemption` list
	if valid, group := p.ValidateExemptions(s); valid {
		log.Printf("GetGroups: found '%v' in exemption list. Will pretend they have access to '%v'", s.Email, group)
		return map[string]string{group: ""}, nil
	}
	log.Printf("GetGroups: looks like no matter how hard we try, we can't verify '%v'", s.Email)
	return map[string]string{}, errors.New("Unable to verify user group membership")
}

// Get group membership on behalf of user
func (p *AzureProvider) GetAllGroupMemberships(s *SessionState, f string) (map[string]string, error) {
	// REST Documentation: https://docs.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0
	// This call permission requirements (any from the list):
	//   - Directory.Read.All
	//   - Directory.ReadWrite.All
	//   - Directory.AccessAsUser.All
	//
	// NOTE: group filter is discarded if list of permitted groups is defined

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

	requestUrl := "https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName,id"
	workaround_set := false

	groups := make(map[string]string, 0)

	for {
		req, err := http.NewRequest("GET", requestUrl, nil)
		// err = errors.New("fake error")

		if err != nil {
			return map[string]string{}, err
		}
		req.Header = getAzureHeader(s.AccessToken)
		req.Header.Add("Content-Type", "application/json")

		groupData, err := api.Request(req)
		if err != nil {
			// If workaround already tried, just fail the execution
			if workaround_set {
				log.Printf("[GetGroups] We tried hard, but still receive error: '%s'", err)
				return map[string]string{}, err
			}

			// It might be that it is a Graph bug, try to workaround it by accessing another URL
			log.Printf("[GetGroups] Failed to get groups details: %s", err)
			// requestUrl = "https://graph.microsoft.com/v1.0/users/" + s.Email + "/memberOf"
			log.Printf("[GetGroups] DETAILS: %s", s)

			requestUrl = "https://graph.microsoft.com/v1.0/users/" + s.Email + "/memberOf$select=displayName,id"
			log.Printf("[GetGroups] Try to workaround by accessing: '%s'", requestUrl)
			workaround_set = true
			continue
		}

		log.Printf("[GetGroups] groupData: %s", groupData)
		for _, groupInfo := range groupData.Get("value").MustArray() {
			v, ok := groupInfo.(map[string]interface{})
			if !ok {
				continue
			}
			dname := v["displayName"].(string)
			if uid, found := v["id"].(string); found {
				if p.GroupPermitted(&dname, &uid) {
					groups[dname] = uid
				}
			} else {
				groups[dname] = ""
			}
		}

		if nextlink := groupData.Get("@odata.nextLink").MustString(); nextlink != "" {
			requestUrl = nextlink
		} else {
			break
		}
	}
	return groups, nil
}

// Verify logged user is member of specific group
func (p *AzureProvider) HasGroupMembership(s *SessionState, gName string, gID string) (bool, error) {
	// Call to `/groups/{GROUPID}/members` has different permission level
	// so if `/me/memberof` failed, there is a slight chance to get lucky here
	//
	// REST Documentation: https://docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0
	// This call permission requirements (any from the list):
	//   - User.ReadBasic.All
	//   - User.Read.All
	//   - Directory.Read.All
	//   - Directory.ReadWrite.All
	//   - Directory.AccessAsUser.All

	if gID == "" {
		log.Printf("HasGroupMembership could not be done for '%v' as group ID is not provided", gName)
		return false, errors.New("missing Group ID")
	}

	if s.ID == "" {
		log.Printf("HasGroupMembership could not be done for '%v' as we don't know current user ID", gName)
		return false, errors.New("missing User ID")
	}

	requestUrl := "https://graph.microsoft.com/v1.0/groups/" + gID + "/members?$filter=id+eq+'" + s.ID + "'&$select=userPrincipalName,id"

	for {
		req, err := http.NewRequest("GET", requestUrl, nil)

		if err != nil {
			return false, err
		}
		req.Header = getAzureHeader(s.AccessToken)
		req.Header.Add("Content-Type", "application/json")

		groupData, err := api.Request(req)
		if err != nil {
			return false, err
		}

		log.Printf("HasGroupMembership groupData: %s", groupData)
		for _, groupInfo := range groupData.Get("value").MustArray() {
			v, ok := groupInfo.(map[string]interface{})
			if !ok {
				continue
			}
			uName := v["userPrincipalName"].(string)
			uID := v["id"].(string)
			if uName == s.Email {
				log.Printf("HasGroupMembership: '%v' is found in '%v'", uName, gName)
				if uID == s.ID {
					log.Printf("HasGroupMembership: '%v' User ID in '%v' matches logged User ID", uName, gName)
					return true, nil
				} else {
					log.Printf("HasGroupMembership: '%v' has User ID in '%v' different to User ID of logged user ('%v' != '%v')", uName, gName, uID, s.ID)
				}
			}
		}

		if nextlink := groupData.Get("@odata.nextLink").MustString(); nextlink != "" {
			requestUrl = nextlink
		} else {
			break
		}
	}
	return false, nil
}

// ValidateExemptions checks if we can allow user login dispite group membership returned failure
func (p *AzureProvider) ValidateExemptions(s *SessionState) (bool, string) {
	log.Printf("ValidateExemptions: validating for %v : %v", s.Email, s.ID)
	for eAccount, eGroup := range p.ExemptedUsers {
		if eAccount == s.Email || eAccount == s.Email+":"+s.ID {
			log.Printf("ValidateExemptions: \t found '%v' user in exemption list. Returning '%v' group membership", eAccount, eGroup)
			return true, eGroup
		}
	}
	return false, ""
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
	// Get list of groups (optionally with Group IDs) that ONLY allowed for user
	// That means even if user has wider group membership, only membership in those groups will be forwarded

	p.PermittedGroups = make(map[string]string)
	if len(groups) == 0 {
		return
	}
	log.Printf("Set group restrictions. Allowed groups are:")
	log.Printf("\t                *GROUP NAME*      : *GROUP ID*")
	for _, pGroup := range groups {
		splittedGroup := strings.Split(pGroup, ":")
		var groupName string
		var groupID string

		if len(splittedGroup) == 1 {
			groupName, groupID = splittedGroup[0], ""
			p.PermittedGroups[splittedGroup[0]] = ""
		} else if len(splittedGroup) > 2 {
			log.Fatalf("failed to parse '%v'. Too many ':' separators", pGroup)
		} else {
			groupName, groupID = splittedGroup[0], splittedGroup[1]
			p.PermittedGroups[splittedGroup[0]] = splittedGroup[1]
		}
		log.Printf("\t - %-30s   %s", groupName, groupID)
	}
	log.Printf("")
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
	log.Printf("Configure user exemption list:")
	log.Printf("\t                    *USER NAME*:*USER ID*                            : *DEFAULT GROUP*")
	for _, pRecord := range exemptions {
		splittedRecord := strings.Split(pRecord, ":")

		if len(splittedRecord) == 1 {
			userRecord, groupName = splittedRecord[0], ""
		} else if len(splittedRecord) == 2 {
			userRecord, groupName = splittedRecord[0], splittedRecord[1]
		} else if len(splittedRecord) > 3 {
			log.Fatalf("failed to parse '%v'. Too many ':' separators", pRecord)
		} else {
			userRecord = splittedRecord[0] + ":" + splittedRecord[1]
			groupName = splittedRecord[2]
		}
		p.ExemptedUsers[userRecord] = groupName
		log.Printf("\t - %-65s    %s", userRecord, groupName)
	}
	log.Printf("")
}

//func (p *AzureProvider) ValidateGroups(groups []string) bool {
//	//
//	// We want to make sure only permitted groups are stored in session
//	// Otherwise user can authorize with one set of groups and then try to change that value in session
//	//
//	if len(p.PermittedGroups) != 0 {
//		for _, gName := range groups {
//			if _, found := p.PermittedGroups[gName]; ! found {
//				log.Printf("Session group list validation error. Group '%v' not found in permitted list", gName)
//				return false
//			}
//		}
//	}
//	return true
//}

func (p *AzureProvider) ValidateGroup(s *SessionState) bool {
	if len(p.PermittedGroups) != 0 {
		log.Printf("VALIDATION: %v", s.Groups)
		for pGroup, _ := range p.PermittedGroups {
			log.Printf("ValidateGroup: %v", pGroup)
			if strings.Contains(s.Groups, pGroup) {
				return true
			}
		}
		return false
	}
	return true
}

func (p *AzureProvider) GroupPermitted(gName *string, gID *string) bool {
	// Validate provided group
	// if "PermitGroups" are defined, for each user group membership, include only those groups that
	// marked in list
	//
	// NOTE: if group in "PermitGroups" does not have group_id defined, this parameter is ignored
	if len(p.PermittedGroups) != 0 {
		for pGroupName, pGroupID := range p.PermittedGroups {
			if pGroupName == *gName {
				log.Printf("ValidateGroup: %v : %v", pGroupName, pGroupID)
				if pGroupID == "" || gID == nil {
					log.Printf("ValidateGroup: %v : %v : no Group ID defined for permitted group. Approving", pGroupName, pGroupID)
					return true
				} else if pGroupID == *gID {
					log.Printf("ValidateGroup: %v : %v : Group ID matches defined in permitted group. Approving", pGroupName, pGroupID)
					return true
				}
				log.Printf("ValidateGroup: %v : %v != %v Group IDs didn't match", pGroupName, pGroupID, *gID)
			}
		}
		return false
	}
	return true
}
