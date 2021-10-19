package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

type PhabricatorProvider struct {
	*ProviderData

	Token       string
	groupFilter *regexp.Regexp
}

var _ Provider = (*PhabricatorProvider)(nil)

// types for the project search endpoint: https://secure.phabricator.com/conduit/method/project.search/
type Constraints struct {
	Members []string `json:"members"`
}

type Conduit struct {
	Token string `json:"token"`
}

type Attachments struct {
	Projects bool `json:"projects"`
}

type ProjectSearch struct {
	Cons Constraints `json:"constraints"`
	Cond Conduit     `json:"__conduit__"`
	Atta Attachments `json:"attachments"`
}

const (
	phabricatorProviderName = "Phabricator"
)

// NewphabricatorProvider creates a phabricatorProvider using the passed ProviderData
func NewPhabricatorProvider(p *ProviderData) *PhabricatorProvider {
	p.setProviderDefaults(providerDefaults{
		name: phabricatorProviderName,
		redeemURL: &url.URL{
			Scheme: p.LoginURL.Scheme,
			Host:   p.Data().LoginURL.Host,
			Path:   "/oauthserver/token/",
		},
		profileURL: &url.URL{
			Scheme: p.LoginURL.Scheme,
			Host:   p.Data().LoginURL.Host,
			Path:   "/api/user.whoami",
		},
		validateURL: &url.URL{
			Scheme: p.LoginURL.Scheme,
			Host:   p.Data().LoginURL.Host,
			Path:   "/api/user.whoami",
		},
	})

	return &PhabricatorProvider{ProviderData: p}
}

// AddGroupFilter adds a regex filter to group listing
func (p *PhabricatorProvider) AddGroupFilter(filter string) error {
	r, err := regexp.Compile(filter)
	if err != nil {
		return err
	}
	p.groupFilter = r
	return nil
}

func (p *PhabricatorProvider) getUsernameAndEmailAddress(ctx context.Context, s *sessions.SessionState) (string, string, error) {
	requestURL := p.ProfileURL.String() + "?access_token=" + s.AccessToken

	json, err := requests.New(requestURL).
		WithContext(ctx).
		Do().
		UnmarshalJSON()
	if err != nil {
		return "", "", err
	}

	result := json.Get("result")

	email, err := result.Get("primaryEmail").String()
	if err != nil {
		return "", "", err
	}

	user, err := result.Get("userName").String()
	if err != nil {
		return "", "", err
	}

	return user, email, nil
}

func (p *PhabricatorProvider) getGroups(ctx context.Context, s *sessions.SessionState) ([]string, error) {
	searchBody := ProjectSearch{
		Constraints{
			Members: []string{s.User},
		},
		Conduit{
			Token: p.Token,
		},
		Attachments{
			Projects: true,
		},
	}

	requestURL := &url.URL{
		Scheme: p.LoginURL.Scheme,
		Host:   p.LoginURL.Host,
		Path:   "/api/project.search",
	}

	jsonBody, _ := json.Marshal(searchBody)
	form := url.Values{}
	form.Add("params", string(jsonBody))

	json, err := requests.New(requestURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(strings.NewReader(form.Encode())).
		Do().
		UnmarshalJSON()
	if err != nil {
		return nil, err
	}

	code, _ := json.Get("error_code").String()
	if code != "" {
		info, _ := json.Get("error_info").String()
		return nil, fmt.Errorf("unable to look up phabricator groups: %s", info)
	}

	var groups []string
	data, _ := json.Get("result").Get("data").Array()
	for i := range data {
		slug, _ := json.Get("result").Get("data").GetIndex(i).Get("fields").Get("slug").String()
		if p.groupFilter == nil || p.groupFilter.MatchString(slug) {
			groups = append(groups, slug)
		}
	}

	return groups, nil
}

// EnrichSession uses the phabricator api to populate the session's email and
// groups.
func (p *PhabricatorProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	user, email, err := p.getUsernameAndEmailAddress(ctx, s)
	if err != nil {
		return err
	}
	s.Email = email
	s.User = user

	groups, err := p.getGroups(ctx, s)
	if err != nil {
		return err
	}

	s.Groups = groups

	return nil
}
