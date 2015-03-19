package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Configuration Options that can be set by Command Line Flag, or Config File
type Options struct {
	HttpAddress  string `flag:"http-address" cfg:"http_address"`
	RedirectUrl  string `flag:"redirect-url" cfg:"redirect_url"`
	ClientID     string `flag:"client-id" cfg:"client_id" env:"GOOGLE_AUTH_PROXY_CLIENT_ID"`
	ClientSecret string `flag:"client-secret" cfg:"client_secret" env:"GOOGLE_AUTH_PROXY_CLIENT_SECRET"`

	AuthenticatedEmailsFile string   `flag:"authenticated-emails-file" cfg:"authenticated_emails_file"`
	GoogleAppsDomains       []string `flag:"google-apps-domain" cfg:"google_apps_domains"`
	HtpasswdFile            string   `flag:"htpasswd-file" cfg:"htpasswd_file"`
	DisplayHtpasswdForm     bool     `flag:"display-htpasswd-form" cfg:"display_htpasswd_form"`
	CustomTemplatesDir      string   `flag:"custom-templates-dir" cfg:"custom_templates_dir"`

	CookieSecret    string        `flag:"cookie-secret" cfg:"cookie_secret" env:"GOOGLE_AUTH_PROXY_COOKIE_SECRET"`
	CookieDomain    string        `flag:"cookie-domain" cfg:"cookie_domain" env:"GOOGLE_AUTH_PROXY_COOKIE_DOMAIN"`
	CookieExpire    time.Duration `flag:"cookie-expire" cfg:"cookie_expire" env:"GOOGLE_AUTH_PROXY_COOKIE_EXPIRE"`
	CookieHttpsOnly bool          `flag:"cookie-https-only" cfg:"cookie_https_only"` // deprecated use cookie-secure
	CookieSecure    bool          `flag:"cookie-secure" cfg:"cookie_secure"`
	CookieHttpOnly  bool          `flag:"cookie-httponly" cfg:"cookie_httponly"`

	Upstreams      []string `flag:"upstream" cfg:"upstreams"`
	SkipAuthRegex  []string `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	PassBasicAuth  bool     `flag:"pass-basic-auth" cfg:"pass_basic_auth"`
	PassHostHeader bool     `flag:"pass-host-header" cfg:"pass_host_header"`

	// internal values that are set after config validation
	redirectUrl   *url.URL
	proxyUrls     []*url.URL
	CompiledRegex []*regexp.Regexp
}

func NewOptions() *Options {
	return &Options{
		HttpAddress:         "127.0.0.1:4180",
		DisplayHtpasswdForm: true,
		CookieHttpsOnly:     true,
		CookieSecure:        true,
		CookieHttpOnly:      true,
		CookieExpire:        time.Duration(168) * time.Hour,
		PassBasicAuth:       true,
		PassHostHeader:      true,
	}
}

func (o *Options) Validate() error {
	msgs := make([]string, 0)
	if len(o.Upstreams) < 1 {
		msgs = append(msgs, "missing setting: upstream")
	}
	if o.CookieSecret == "" {
		msgs = append(msgs, "missing setting: cookie-secret")
	}
	if o.ClientID == "" {
		msgs = append(msgs, "missing setting: client-id")
	}
	if o.ClientSecret == "" {
		msgs = append(msgs, "missing setting: client-secret")
	}

	redirectUrl, err := url.Parse(o.RedirectUrl)
	if err != nil {
		msgs = append(msgs, fmt.Sprintf(
			"error parsing redirect-url=%q %s", o.RedirectUrl, err))
	}
	o.redirectUrl = redirectUrl

	for _, u := range o.Upstreams {
		upstreamUrl, err := url.Parse(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error parsing upstream=%q %s",
				upstreamUrl, err))
		}
		if upstreamUrl.Path == "" {
			upstreamUrl.Path = "/"
		}
		o.proxyUrls = append(o.proxyUrls, upstreamUrl)
	}

	for _, u := range o.SkipAuthRegex {
		CompiledRegex, err := regexp.Compile(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error compiling regex=%q %s", u, err))
		}
		o.CompiledRegex = append(o.CompiledRegex, CompiledRegex)
	}

	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}
