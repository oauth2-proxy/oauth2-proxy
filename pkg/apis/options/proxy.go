package options

type ProxyOptions struct {
	// security
	AllowQuerySemicolons  bool     `yaml:"allowQuerySemicolons,omitempty"`
	ForceHTTPS            bool     `yaml:"forceHttps,omitempty"`
	SkipAuthRegex         []string `yaml:"skipAuthRegex,omitempty"`
	SkipAuthRoutes        []string `yaml:"skipAuthRoutes,omitempty"`
	SkipAuthPreflight     bool     `yaml:"skipAuthPreflight,omitempty"`
	SSLInsecureSkipVerify bool     `yaml:"sslInsecureSkipVerify,omitempty"`
	TrustedIPs            []string `yaml:"trustedIPs,omitempty"`

	// authentication
	AuthenticatedEmailsFile string   `yaml:"authenticatedEmailsFile,omitempty"`
	EmailDomains            []string `yaml:"emailDomains,omitempty"`
	WhitelistDomains        []string `yaml:"whitelistDomains,omitempty"`
	HtpasswdFile            string   `yaml:"htpasswdFile,omitempty"`
	HtpasswdUserGroups      []string `yaml:"htpasswdUserGroups,omitempty"`
	SkipJwtBearerTokens     bool     `yaml:"skipJwtBearerTokens,omitempty"`
	ExtraJwtIssuers         []string `yaml:"extraJwtIssuers,omitempty"`

	// routing
	APIRoutes           []string `yaml:"apiRoutes,omitempty"`
	ReverseProxy        bool     `yaml:"reverseProxy,omitempty"`
	ProxyPrefix         string   `yaml:"proxyPrefix,omitempty"`
	RedirectURL         string   `yaml:"redirectUrl,omitempty"`
	RelativeRedirectURL bool     `yaml:"relativeRedirectUrl,omitempty"`
	RealClientIPHeader  string   `yaml:"realClientIPHeader,omitempty"`
	SkipProviderButton  bool     `yaml:"skipProviderButton,omitempty"`
	EncodeState         bool     `yaml:"encodeState,omitempty"`

	// Force oauth2-proxy error responses to be JSON
	ForceJSONErrors bool `yaml:"forceJsonErrors,omitempty"`

	// This is used for backwards compatibility
	LegacyPreferEmailToUser bool   `yaml:"legacyPreferEmailToUser,omitempty"`
	LegacySignatureKey      string `yaml:"legacySignatureKey,omitempty"`
}

func proxyOptionsDefaults() ProxyOptions {
	return ProxyOptions{
		ProxyPrefix:        "/oauth2",
		RealClientIPHeader: "X-Real-IP",
	}
}
