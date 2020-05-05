package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

// NextcloudProvider represents an Nextcloud based Identity Provider
type NextcloudProvider struct {
	*ProviderData
}

var _ Provider = (*NextcloudProvider)(nil)

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
func (p *NextcloudProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
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
