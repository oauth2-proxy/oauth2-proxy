package options

import (
	"crypto"
	"net/url"
	"time"
)

// SignatureData holds hmacauth signature hash and key
type SignatureData struct {
	Hash crypto.Hash
	Key  string
}

// Options holds Configuration Options that can be set by Command Line Flag,
// or Config File
type Options struct {
	ProxyPrefix         string `mapstructure:"proxy_prefix"`
	ReverseProxy        bool   `mapstructure:"reverse_proxy"`
	RawRedirectURL      string `mapstructure:"redirect_url"`
	RelativeRedirectURL bool   `mapstructure:"relative_redirect_url"`

	WhitelistDomains []string `mapstructure:"whitelist_domains"`

	Cookie          Cookie          `mapstructure:",squash"`
	Session         SessionOptions  `mapstructure:",squash"`
	Service         Service         `mapstructure:",squash"`
	ValidateService ValidateService `mapstructure:",squash"`
	MatchRules      MatchRules      `mapstructure:",squash"`

	Providers Providers

	SkipAuthPreflight bool `mapstructure:"skip_auth_preflight"`
	EncodeState       bool `mapstructure:"encode_state"`
	PassAuthorization bool `mapstructure:"pass_authorization_header"`
	PassAccessToken   bool `mapstructure:"pass_access_token"`

	VerifierInterval   time.Duration `mapstructure:"verifier_interval"`
	UpdateKeysInterval time.Duration `mapstructure:"update_keys_interval"`
	// internal values that are set after config validation
	redirectURL *url.URL // 私有字段通常不需要 mapstructure 标签
}

// Options for Getting internal values
func (o *Options) GetRedirectURL() *url.URL { return o.redirectURL }

// Options for Setting internal values
func (o *Options) SetRedirectURL(s *url.URL) {
	o.redirectURL = s
	o.MatchRules.RedirectURL = s
}

// NewOptions constructs a new Options with defaulted values
func NewOptions() *Options {
	return &Options{
		ProxyPrefix:        "/oauth2",
		Providers:          providerDefaults(),
		Cookie:             cookieDefaults(),
		Session:            sessionOptionsDefaults(),
		SkipAuthPreflight:  false,
		PassAuthorization:  true,
		PassAccessToken:    false,
		VerifierInterval:   2 * time.Second, // 5 seconds
		UpdateKeysInterval: 24 * time.Hour,  // 24 hours
		MatchRules:         matchRulesDefaults(),
	}
}
