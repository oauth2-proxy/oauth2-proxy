package providers

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"golang.org/x/oauth2"
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
	AcrValues           string
	ApprovalPrompt      string // NOTE: Renamed to "prompt" in OAuth2
	ClientID            string
	ClientSecret        string
	ClientSecretFile    string
	Scope               string
	Prompt              string
	UseOIDCImplicitFlow bool
	OIDCIssuerURL       string
}

type TokenRelatedConfig struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

var (
	// ParsedConfig is the parsed config
	ParsedConfig TokenRelatedConfig
)

// Data returns the ProviderData
func (p *ProviderData) Data() *ProviderData { return p }

func (p *ProviderData) GetClientSecret() (clientSecret string, err error) {
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

func (p *ProviderData) GetSigningKey(redirectURL string) (returnSigningKey *rsa.PublicKey, err error) {
	OAuth2Config := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Scopes:       []string{p.Scope},
		RedirectURL:  redirectURL,
	}

	u, err := url.Parse(p.OIDCIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed tp get oidc issuer url :%v", p.OIDCIssuerURL)
	}

	u.Path = path.Join(u.Path, ".well-known/openid-configuration")
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get openid configuration with path:%v, err:%v ", u.String(), err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to get response body, err:%v", err)
	}

	err = json.Unmarshal(body, &ParsedConfig)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	OAuth2Config.Endpoint = oauth2.Endpoint{
		AuthURL:   ParsedConfig.AuthorizationEndpoint,
		TokenURL:  ParsedConfig.TokenEndpoint,
		AuthStyle: oauth2.AuthStyleAutoDetect,
	}

	keySet, err := jwk.Fetch(ParsedConfig.JwksURI)
	if err != nil {
		panic(err)
	}

	var signingKey rsa.PublicKey
	err = keySet.Keys[0].Raw(&signingKey)
	if err != nil {
		panic(err)
	}
	returnSigningKey = &signingKey
	return returnSigningKey, nil
}
