package options

type ProxyOptions struct {
	// networking
	ProxyPrefix           string   `json:"proxyPrefix,omitempty"`
	RealClientIPHeader    string   `json:"realClientIPHeader,omitempty"`
	ReverseProxy          bool     `json:"reverseProxy,omitempty"`
	TrustedIPs            []string `json:"trustedIPs,omitempty"`
	ForceHTTPS            bool     `json:"forceHttps,omitempty"`
	ForceJSONErrors       bool     `json:"forceJsonErrors,omitempty"`
	AllowQuerySemicolons  bool     `json:"allowQuerySemicolons,omitempty"`
	SSLInsecureSkipVerify bool     `json:"sslInsecureSkipVerify,omitempty"`
	SkipAuthRegex         []string `json:"skipAuthRegex,omitempty"`
	SkipAuthRoutes        []string `json:"skipAuthRoutes,omitempty"`

	// authentication
	AuthenticatedEmailsFile string   `json:"authenticatedEmailsFile,omitempty"`
	EmailDomains            []string `json:"emailDomains,omitempty"`
	WhitelistDomains        []string `json:"whitelistDomains,omitempty"`
	HtpasswdFile            string   `json:"htpasswdFile,omitempty"`
	HtpasswdUserGroups      []string `json:"htpasswdUserGroups,omitempty"`

	// proxy
	RedirectURL         string   `json:"redirectUrl,omitempty"`
	RelativeRedirectURL bool     `json:"relativeRedirectUrl,omitempty"`
	APIRoutes           []string `json:"apiRoutes,omitempty"`
	SkipJwtBearerTokens bool     `json:"skipJwtBearerTokens,omitempty"`
	ExtraJwtIssuers     []string `json:"extraJwtIssuers,omitempty"`
	SkipProviderButton  bool     `json:"skipProviderButton,omitempty"`
	SkipAuthPreflight   bool     `json:"skipAuthPreflight,omitempty"`
}

func proxyOptionsDefaults() ProxyOptions {
	return ProxyOptions{
		ProxyPrefix:        "/oauth2",
		RealClientIPHeader: "X-Real-IP",
		ForceHTTPS:         false,
		SkipAuthPreflight:  false,
	}
}
