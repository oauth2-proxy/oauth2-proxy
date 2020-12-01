package providers

import (
	"errors"
	"io/ioutil"
	"net/url"

	"github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// ProviderData contains information required to configure all implementations
// of OAuth2 providers
type ProviderData struct {
	ProviderName      string
	LoginURL          *url.URL
	RedeemURL         *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	ValidateURL       *url.URL
	// Auth request params & related, see
	//https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.1.1.1
	AcrValues        string
	ApprovalPrompt   string // NOTE: Renamed to "prompt" in OAuth2
	ClientID         string
	ClientSecret     string
	ClientSecretFile string
	Scope            string
	Prompt           string
	Verifier         *oidc.IDTokenVerifier

	// Universal Group authorization data structure
	// any provider can set to consume
	AllowedGroups map[string]struct{}
}

// Data returns the ProviderData
func (p *ProviderData) Data() *ProviderData { return p }

func (p *ProviderData) GetClientSecret() (clientSecret string, err error) {
	if p.ClientSecret != "" || p.ClientSecretFile == "" {
		return p.ClientSecret, nil
	}

	// Getting ClientSecret can fail in runtime so we need to report it without returning the file name to the user
	fileClientSecret, err := ioutil.ReadFile(p.ClientSecretFile)
	if err != nil {
		logger.Errorf("error reading client secret file %s: %s", p.ClientSecretFile, err)
		return "", errors.New("could not read client secret file")
	}
	return string(fileClientSecret), nil
}

// SetAllowedGroups organizes a group list into the AllowedGroups map
// to be consumed by Authorize implementations
func (p *ProviderData) SetAllowedGroups(groups []string) {
	p.AllowedGroups = make(map[string]struct{}, len(groups))
	for _, group := range groups {
		p.AllowedGroups[group] = struct{}{}
	}
}

type providerDefaults struct {
	name        string
	loginURL    *url.URL
	redeemURL   *url.URL
	profileURL  *url.URL
	validateURL *url.URL
	scope       string
}

func (p *ProviderData) setProviderDefaults(defaults providerDefaults) {
	p.ProviderName = defaults.name
	p.LoginURL = defaultURL(p.LoginURL, defaults.loginURL)
	p.RedeemURL = defaultURL(p.RedeemURL, defaults.redeemURL)
	p.ProfileURL = defaultURL(p.ProfileURL, defaults.profileURL)
	p.ValidateURL = defaultURL(p.ValidateURL, defaults.validateURL)

	if p.Scope == "" {
		p.Scope = defaults.scope
	}
}

// defaultURL will set return a default value if the given value is not set.
func defaultURL(u *url.URL, d *url.URL) *url.URL {
	if u != nil && u.String() != "" {
		// The value is already set
		return u
	}

	// If the default is given, return that
	if d != nil {
		return d
	}
	return &url.URL{}
}
