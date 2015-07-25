package providers

import (
	"net/url"
)

type ProviderData struct {
	ProviderName   string
	ClientID       string
	ClientSecret   string
	LoginUrl       *url.URL
	RedeemUrl      *url.URL
	ProfileUrl     *url.URL
	ValidateUrl    *url.URL
	Scope          string
	ApprovalPrompt string
}

func (p *ProviderData) Data() *ProviderData { return p }
