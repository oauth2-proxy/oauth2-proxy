package providers

import (
	"fmt"
	"net/http"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

// NextcloudProvider represents an Nextcloud based Identity Provider
type NextcloudProvider struct {
	*ProviderData
}

// NewNextcloudProvider initiates a new NextcloudProvider
func NewNextcloudProvider(p *ProviderData) *NextcloudProvider {
	p.ProviderName = "Nextcloud"
	return &NextcloudProvider{ProviderData: p}
}

func getNextcloudHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetEmailAddress returns the Account email address
func (p *NextcloudProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	req, err := http.NewRequest("GET",
		p.ValidateURL.String(), nil)
	if err != nil {
		logger.Printf("failed building request %s", err)
		return "", err
	}
	req.Header = getNextcloudHeader(s.AccessToken)
	json, err := requests.Request(req)
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}
	email, err := json.Get("ocs").Get("data").Get("email").String()
	return email, err
}
