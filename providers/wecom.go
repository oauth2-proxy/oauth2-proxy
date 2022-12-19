package providers

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// WeComProvider represents an WeCom based Identity Provider
type WeComProvider struct {
	*ProviderData
	CorpId        string
	CorpAccessToken           string
	CorpAccessTokenURL        url.URL
	CorpAccessTokenExpiration time.Time
	NonSensitiveProfileURL    url.URL
}

const (
	wecomProviderName = "WeCom"
	wecomDefaultScope = "snsapi_privateinfo"
)

var (
	// Default CorpAccessToken URL for WeCom.
	// Pre-parsed URL of https://qyapi.weixin.qq.com/cgi-bin/gettoken.
	wecomDefaultCorpAccessTokenURL = &url.URL{
		Scheme: "https",
		Host:   "qyapi.weixin.qq.com",
		Path:   "/cgi-bin/gettoken",
	}

	// Default Login URL for WeCom.
	// Pre-parsed URL of https://open.weixin.qq.com/connect/oauth2/authorize.
	wecomDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "open.weixin.qq.com",
		Path:   "/connect/oauth2/authorize",
	}

	// Default Redeem URL for WeCom.
	// Pre-parsed URL of https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo.
	wecomDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "qyapi.weixin.qq.com",
		Path:   "/cgi-bin/auth/getuserinfo",
	}

	// Default Profile URL for WeCom.
	// Pre-parsed URL of https://qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail.
	wecomDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "qyapi.weixin.qq.com",
		Path:   "/cgi-bin/auth/getuserdetail",
	}

	// Default NonSensitive Profile URL for WeCom.
	// Pre-parsed URL of https://qyapi.weixin.qq.com/cgi-bin/user/get.
	wecomDefaultNonSensitiveProfileURL = &url.URL{
		Scheme: "https",
		Host:   "qyapi.weixin.qq.com",
		Path:   "/cgi-bin/user/get",
	}
)

// NewWeComProvider initiates a new WeComProvider
func NewWeComProvider(p *ProviderData, opts options.WeComOptions) *WeComProvider {
	p.setProviderDefaults(providerDefaults{
		name:        wecomProviderName,
		loginURL:    wecomDefaultLoginURL,
		redeemURL:   wecomDefaultRedeemURL,
		profileURL:  wecomDefaultProfileURL,
		validateURL: wecomDefaultProfileURL,
		scope:       wecomDefaultScope,
	})

	return &WeComProvider{
		ProviderData:              p,
		CorpId:                    opts.CorpId,
		CorpAccessToken:           "",
		CorpAccessTokenURL:        *wecomDefaultCorpAccessTokenURL,
		CorpAccessTokenExpiration: time.Unix(0, 0),
		NonSensitiveProfileURL:    *wecomDefaultNonSensitiveProfileURL,
	}
}

var _ Provider = (*WeComProvider)(nil)


// GetLoginURL makes the LoginURL with optional appid/agentid support
func (p *WeComProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	extraParams.Add("appid", p.CorpId)
	if p.Scope == "snsapi_privateinfo" {
		extraParams.Add("agentid", p.ClientID)
	}
	loginURL := makeLoginURL(p.Data(), redirectURI, state, extraParams)
	return loginURL.String()
}

// Redeem exchanges the OAuth2 authentication code for an User Ticket
func (p *WeComProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	// get
	corpAccessToken, err := p.getCorpAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	
	var jsonResponse struct {
		ErrorCode    int    `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
		UserId       string `json:"userid"`
		UserTicket   string `json:"user_ticket"`
	}

	err = requests.New(p.RedeemURL.String() + "?access_token=" + corpAccessToken).
		WithContext(ctx).
		WithMethod("GET").
		SetHeader("Content-Type", "application/json").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	s := &sessions.SessionState{
		User:         jsonResponse.UserId,
		AccessToken:  jsonResponse.UserTicket,
		IDToken:      "",
		RefreshToken: "",
	}
	s.CreatedAtNow()
	s.SetExpiresOn(time.Now().Add(time.Duration(1800 - 300) * time.Second))
	
	err = p.enrichNonSensitiveData(ctx, s)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// GetEmailAddress returns the Account email address
func (p *WeComProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.Email == "" {
		err := p.enrichSensitiveData(ctx, s)
		if err != nil {
			return "", err
		}
	}
	return s.Email, nil
}

func (p *WeComProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if s.Email == "" {
		return p.enrichSensitiveData(ctx, s)
	}
	return nil
}

// ValidateSession validates the AccessToken
func (p *WeComProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	err := p.enrichSensitiveData(ctx, s)
	if err != nil {
		return false
	}
	return true
}

// Acquire CorpAccessToken before access oauth2 api
func (p *WeComProvider) getCorpAccessToken(ctx context.Context) (string, error) {
	// return directly if valid
	if p.CorpAccessToken != "" && p.CorpAccessTokenExpiration.After(time.Now())  {
		return p.CorpAccessToken, nil
	}

	var jsonResponse struct {
		ErrorCode    int    `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
	}

	// corpsecret is appsecret
	corpSecret, err := p.GetClientSecret()
	if err != nil {
		return "", err
	}

	err = requests.New(p.CorpAccessTokenURL.String() + "?corpid=" + p.CorpId + "&corpsecret=" + corpSecret).
		WithContext(ctx).
		WithMethod("GET").
		SetHeader("Content-Type", "application/json").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return "", err
	}

	if jsonResponse.ErrorCode == 0 && jsonResponse.AccessToken != "" {
		p.CorpAccessToken = jsonResponse.AccessToken
		p.CorpAccessTokenExpiration = time.Now().Add(time.Duration(jsonResponse.ExpiresIn - 300) * time.Second)
		return p.CorpAccessToken, nil
	} else {
		return "", fmt.Errorf(jsonResponse.ErrorMessage)
	}
}

func (p *WeComProvider) enrichNonSensitiveData(ctx context.Context, s *sessions.SessionState) error {
	// Corp Access Token
	corpAccessToken, err := p.getCorpAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire corp access token: %v", err)
	}

	var jsonResponse struct {
		ErrorCode    int    `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
		UserId       string `json:"userid"`
		Name         string `json:"name"`
		Department   []string  `json:"department"`
		// Position     string `json:"position"`
	}

	err = requests.New(p.NonSensitiveProfileURL.String() + "?access_token=" + corpAccessToken + "&userid=" + s.User).
		WithContext(ctx).
		WithMethod("GET").
		SetHeader("Content-Type", "application/json").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return fmt.Errorf("failed to acquire employee non-sensitive data: %v", err)
	}

	s.Groups = jsonResponse.Department
	s.PreferredUsername = jsonResponse.Name

	return nil
}

func (p *WeComProvider) enrichSensitiveData(ctx context.Context, s *sessions.SessionState) error {
	// Corp Access Token
	corpAccessToken, err := p.getCorpAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire corp access token: %v", err)
	}

	var jsonResponse struct {
		ErrorCode    int    `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
		UserId       string `json:"userid"`
		// Gender       string `json:"gender"`
		// Avatar       string `json:"avatar"`
		// QRCode       string `json:"qr_code"`
		// Mobile       string `json:"mobile"`
		Email        string `json:"email"`
		BizEmail     string `json:"biz_email"`
		// Address      string `json:"address"`
	}

	params := url.Values{}
	params.Add("user_ticket", s.AccessToken)

	err = requests.New(p.ProfileURL.String() + "?access_token=" + corpAccessToken).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/json").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return err
	}

	if jsonResponse.Email != "" {
		s.Email = jsonResponse.Email
	} else {
		s.Email = jsonResponse.BizEmail
	}

	return nil
}