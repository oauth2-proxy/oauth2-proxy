package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Jing-ze/oauth2-proxy/pkg/apis/sessions"
	"github.com/Jing-ze/oauth2-proxy/pkg/util"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
)

type AliyunProvider struct {
	*ProviderData
}

const (
	aliyunProviderName = "Aliyun"
	aliyunDefaultScope = "openid"
)

var (
	aliyunDefaultLoginURL = &url.URL{
		Scheme:   "https",
		Host:     "signin.aliyun.com",
		Path:     "/oauth2/v1/auth",
		RawQuery: "access_type=offline",
	}

	aliyunDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "oauth.aliyun.com",
		Path:   "/v1/token",
	}
)

func NewAliyunProvider(p *ProviderData) *AliyunProvider {
	p.setProviderDefaults(providerDefaults{
		name:        aliyunProviderName,
		loginURL:    aliyunDefaultLoginURL,
		redeemURL:   aliyunDefaultRedeemURL,
		profileURL:  nil,
		validateURL: nil,
		scope:       aliyunDefaultScope,
	})

	provider := &AliyunProvider{ProviderData: p}

	return provider
}

var _ Provider = (*AliyunProvider)(nil)

func (p *AliyunProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")

	headers := [][2]string{{"Content-Type", "application/x-www-form-urlencoded"}}

	client.Post(p.RedeemURL.String(), headers, []byte(params.Encode()), func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		token, err := util.UnmarshalToken(responseHeaders, responseBody)
		if err != nil {
			util.SendError(err.Error(), nil, http.StatusInternalServerError)
			return
		}
		id_token, ok := token.Extra("id_token").(string)
		if !ok {
			util.SendError("id_token not found", nil, http.StatusInternalServerError)
			return
		}
		session := &sessions.SessionState{
			IDToken:      id_token,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
		}
		session.CreatedAtNow()
		session.SetExpiresOn(token.Expiry)

		callback(session)
	}, timeout)

	return nil
}

func (p *AliyunProvider) RefreshSession(ctx context.Context, s *sessions.SessionState, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, fmt.Errorf("refresh token is empty")
	}

	err := p.redeemRefreshToken(ctx, s, client, callback, timeout)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	return true, nil
}

func (p *AliyunProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")

	headers := [][2]string{{"Content-Type", "application/x-www-form-urlencoded"}}

	client.Post(p.RedeemURL.String(), headers, []byte(params.Encode()), func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		token, err := util.UnmarshalToken(responseHeaders, responseBody)
		if err != nil {
			util.SendError(err.Error(), nil, http.StatusInternalServerError)
			return
		}
		s.AccessToken = token.AccessToken
		s.CreatedAtNow()
		s.SetExpiresOn(token.Expiry)

		callback(s, true)
	}, timeout)

	return nil
}
