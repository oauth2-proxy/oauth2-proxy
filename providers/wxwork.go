package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// WxWorkProvider represents an WxWork based Identity Provider
type WxWorkProvider struct {
	*ProviderData
	CorpId        string
	CorpAccessToken           string
	CorpAccessTokenExpiration time
}

const (
	wxworkProviderName = "WxWork"
	wxworkDefaultScope = "snsapi_privateinfo"

	// Default CorpAccessToken URL for WxWork.
	// Pre-parsed URL of https://qyapi.weixin.qq.com/cgi-bin/gettoken.
	wxworkDefaultCorpAccessTokenURL = &url.URL{
		Scheme: "https",
		Host:   "qyapi.weixin.qq.com",
		Path:   "/cgi-bin/gettoken",
	}

	// Default Login URL for WxWork.
	// Pre-parsed URL of https://open.weixin.qq.com/connect/oauth2/authorize.
	wxworkDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "open.weixin.qq.com",
		Path:   "/connect/oauth2/authorize",
	}

	// Default Redeem URL for WxWork.
	// Pre-parsed URL of https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo.
	wxworkDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "qyapi.weixin.qq.com",
		Path:   "/cgi-bin/auth/getuserinfo",
	}

	// Default Profile URL for WxWork.
	// Pre-parsed URL of https://qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail.
	wxworkDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "qyapi.weixin.qq.com",
		Path:   "/cgi-bin/auth/getuserdetail",
	}
)

// NewWxWorkProvider initiates a new WxWorkProvider
func NewWxWorkProvider(p *ProviderData, opts options.WxWorkOptions) *WxWorkProvider {
	p.setProviderDefaults(providerDefaults{
		name:        wxworkProviderName,
		loginURL:    wxworkDefaultLoginURL,
		redeemURL:   wxworkDefaultRedeemURL,
		profileURL:  wxworkDefaultProfileURL,
		validateURL: wxworkDefaultProfileURL,
		scope:       wxworkDefaultScope,
	})

	return &WxWorkProvider{
		ProviderData:       p,
		CorpId:             opts.CorpId,
		CorpAccessTokenUrl: wxworkDefaultCorpAccessTokenURL,
	}
}

var _ Provider = (*WxWorkProvider)(nil)


// GetLoginURL makes the LoginURL with optional appid/agentid support
func (p *WxWorkProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	if !p.SkipNonce {
		extraParams.Add("appid", p.CorpId)
		extraParams.Add("agentid", p.ClientID)
	}
	loginURL := makeLoginURL(p.Data(), redirectURI, state, extraParams)
	return loginURL.String()
}

// Redeem exchanges the OAuth2 authentication code for an User Ticket
func (p *WxWorkProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	// get
	corpAccessToken, err := getCorpAcessToken()
	if err != nil {
		return nil, err
	}
	
	var jsonResponse struct {
		ErrorCode    string `json:"errcode"`
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

	session := &sessions.SessionState{
		User:         jsonResponse.UserId,
		AccessToken:  nil,
		IDToken:      jsonResponse.UserTicket,
		RefreshToken: nil,
	}
	session.CreatedAtNow()
	session.SetExpiresOn(time.Unix(time.Now().Add(1800*time.Second)))

	return session, nil
}

// Acquire CorpAccessToken before access oauth2 api
func (p *WxWorkProvider) getCorpAcessToken(ctx context.Context) (string, error) {
	// return directly if valid
	if p.CorpAccessToken != nil && p.CorpAccessToken != "" && p.CorpAccessTokenExpiration.After(time.Now())  {
		return p.CorpAccessToken, nil
	}

	var jsonResponse struct {
		ErrorCode    string `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
		AccessToken  string `json:"access_token"`
		ExpiresIn    string `json:"expires_in"`
	}

	// corpsecret is appsecret
	corpSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	err = requests.New(p.CorpAccessTokenUrls.String() + "?corpid=" + p.CorpId + "&corpsecret=" + corpSecret).
		WithContext(ctx).
		WithMethod("GET").
		SetHeader("Content-Type", "application/json").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	if jsonResponse.ErrorCode == 0 && jsonResponse.AccesToken != nil && jsonResponse.AccessToken != "" {
		p.CorpAccessToken = jsonResponse.AccessToken
		p.CorpAccessTokenExpiration = time.Now().Add(jsonResponse.ExpiresIn*time.Second).Minus(300*time.Second)
	} else {
		return nil, jsonResponse.ErrorMessage
	}
}

// GetEmailAddress returns the Account email address
func (p *WxWorkProvider) GetEmailAddress(ctx context.Context, session *sessions.SessionState) (string, error) {

	accessToken := ""

	var jsonResponse struct {
		ErrorCode    string `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
		UserId       string `json:"userid"`
		Gender       string `json:"gender"`
		Avatar       string `json:"avatar"`
		QRCode       string `json:"qr_code"`
		Mobile       string `json:"mobile"`
		Email        string `json:"email"`
		BizEmail     string `json:"biz_email"`
		Address      string `json:"address"`
	}

	params := url.Values{}
	params.Add("user_ticket", session.IDToken)

	err = requests.New(p.ProfileURL.String() + "?access_token=" + accessToken).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/json").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	return jsonResponse.Email, nil
}

