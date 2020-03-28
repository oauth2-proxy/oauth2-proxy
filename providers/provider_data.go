package providers

import (
	"errors"
	"io/ioutil"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/logger"
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
}

// Data returns the ProviderData
func (p *ProviderData) Data() *ProviderData { return p }

func (p *ProviderData) GetClientSecret() (ClientSecret string, err error) {
	if p.ClientSecret != "" || p.ClientSecretFile == "" {
		return p.ClientSecret, nil
	}

	// Getting ClientSecret can fail in runtime so we need to report it without returning the file name to the user
	fileClientSecret, err := ioutil.ReadFile(p.ClientSecretFile)
	if err != nil {
		logger.Printf("error reading client secret file %s: %s", p.ClientSecretFile, err)
		return "", errors.New("could not read client secret file")
	}
	return string(fileClientSecret), nil
}
