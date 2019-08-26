package providers

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

// CarolProvider represents an Carol based Identity Provider
type CarolProvider struct {
	*ProviderData
}

// NewCarolProvider initiates a new CarolProvider
func NewCarolProvider(p *ProviderData) *CarolProvider {
	p.ProviderName = "Carol"
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			//Host:   "%s.%s.%s.ai",
			Host: "%s.%s.ai",
			Path: "/api/v2/oauth2/token/",
		}
	}
	return &CarolProvider{ProviderData: p}
}

// GetEmailAddress returns the Client Id
func (p *CarolProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET",
		p.ValidateURL.String()+s.AccessToken, nil)
	if err != nil {
		logger.Printf("failed building request %s", err)
		return "", err
	}
	// NOTE this !!
	//req.Close = true
	json, err := requests.Request(req)
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}
	return json.Get("client_id").String()
}

// ValidateSessionState returns the Client Id
func (p *CarolProvider) ValidateSessionState(s *sessions.SessionState) bool {
	accessToken := s.AccessToken
	if accessToken == "" || p.Data().ValidateURL == nil || p.Data().ValidateURL.String() == "" {
		return false
	}
	endpoint := p.Data().ValidateURL.String() + accessToken
	resp, err := requests.RequestUnparsedResponse(endpoint, nil)
	if err != nil {
		logger.Printf("GET %s", stripToken(endpoint))
		logger.Printf("token validation request failed: %s", err)
		return false
	}

	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	logger.Printf("%d GET %s %s", resp.StatusCode, stripToken(endpoint), body)

	if resp.StatusCode == 200 {
		return true
	}
	logger.Printf("token validation request failed: status %d - %s", resp.StatusCode, body)
	return false
}
