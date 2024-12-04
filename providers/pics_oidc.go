package providers

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// enrichFromIntrospectURL enriches a session's claims and permissions via the JSON response of
// an OIDC Introspection URL
func (p *OIDCProvider) PicsEnrichFromIntrospectURL(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Add("token", s.AccessToken)
	basicAuth := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", p.ClientID, clientSecret)))
	if p.IntrospectURL == nil {
		p.IntrospectURL = &url.URL{
			Scheme: p.RedeemURL.Scheme,
			Host:   p.RedeemURL.Host,
			Path:   "/authorize/oauth2/v4/introspect",
		}
	}
	logger.Printf("Requesting introspect from '%s'", p.IntrospectURL)

	result := requests.New(p.IntrospectURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Authorization", fmt.Sprintf("Basic %s", basicAuth)).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()

	if result.StatusCode() != http.StatusOK {
		return fmt.Errorf("error while requesting introspect claims, status code - %d", result.StatusCode())
	}
	s.IntrospectClaims = b64.StdEncoding.EncodeToString(result.Body())
	return nil
}
