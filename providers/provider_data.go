package providers

import (
	"net/url"
)

type ProviderData struct {
	ProviderName string
	LoginUrl     *url.URL
	RedeemUrl    *url.URL
	ProfileUrl   *url.URL
	Scope        string
}

func (p *ProviderData) Data() *ProviderData { return p }
