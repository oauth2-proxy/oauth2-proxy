package options

type ProxyOptions struct {
	// security
	AllowQuerySemicolons  bool     `json:"allowQuerySemicolons,omitempty"`
	ForceHTTPS            bool     `json:"forceHttps,omitempty"`
	SkipAuthRegex         []string `json:"skipAuthRegex,omitempty"`
	SkipAuthRoutes        []string `json:"skipAuthRoutes,omitempty"`
	SkipAuthPreflight     bool     `json:"skipAuthPreflight,omitempty"`
	SSLInsecureSkipVerify bool     `json:"sslInsecureSkipVerify,omitempty"`
	TrustedIPs            []string `json:"trustedIPs,omitempty"`

	// authentication
	AuthenticatedEmailsFile string   `json:"authenticatedEmailsFile,omitempty"`
	EmailDomains            []string `json:"emailDomains,omitempty"`
	WhitelistDomains        []string `json:"whitelistDomains,omitempty"`
	HtpasswdFile            string   `json:"htpasswdFile,omitempty"`
	HtpasswdUserGroups      []string `json:"htpasswdUserGroups,omitempty"`
	SkipJwtBearerTokens     bool     `json:"skipJwtBearerTokens,omitempty"`
	ExtraJwtIssuers         []string `json:"extraJwtIssuers,omitempty"`

	// routing
	APIRoutes           []string `json:"apiRoutes,omitempty"`
	ReverseProxy        bool     `json:"reverseProxy,omitempty"`
	ProxyPrefix         string   `json:"proxyPrefix,omitempty"`
	RedirectURL         string   `json:"redirectUrl,omitempty"`
	RelativeRedirectURL bool     `json:"relativeRedirectUrl,omitempty"`
	RealClientIPHeader  string   `json:"realClientIPHeader,omitempty"`
	SkipProviderButton  bool     `json:"skipProviderButton,omitempty"`
	EncodeState         bool     `json:"encodeState,omitempty"`

	// Force oauth2-proxy error responses to be JSON
	ForceJSONErrors bool `json:"forceJsonErrors,omitempty"`

	// This is used for backwards compatibility
	LegacyPreferEmailToUser bool   `json:"legacyPreferEmailToUser,omitempty"`
	LegacySignatureKey      string `json:"legacySignatureKey,omitempty"`
}

func proxyOptionsDefaults() ProxyOptions {
	return ProxyOptions{
		ProxyPrefix:        "/oauth2",
		RealClientIPHeader: "X-Real-IP",
	}
}
