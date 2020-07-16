package options

import (
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
	"github.com/spf13/pflag"
)

// Authorization holds configuration options related to trusted requests which
// would skip authentication
type Authorization struct {
	SkipAuthRegex        []string `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	SkipAuthRoutes       []string `flag:"skip-auth-route" cfg:"skip_auth_routes"`
	SkipAuthPreflight    bool     `flag:"skip-auth-preflight" cfg:"skip_auth_preflight"`
	SkipAuthStripHeaders bool     `flag:"skip-auth-strip-headers" cfg:"skip_auth_strip_headers"`
	TrustedIPs           []string `flag:"trusted-ip" cfg:"trusted_ips"`

	// internal set after validation
	rulesEngine authorization.RulesEngine
}

// GetRulesEngine gets the private rules engine
func (a *Authorization) GetRulesEngine() authorization.RulesEngine {
	return a.rulesEngine
}

// SetRulesEngine sets the private rules engine
func (a *Authorization) SetRulesEngine(e authorization.RulesEngine) {
	a.rulesEngine = e
}

// authorizationFlagSet creates a new FlagSet with all of the flags required by Authorization
func authorizationFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("authorization", pflag.ExitOnError)

	flagSet.StringSlice("skip-auth-regex", []string{}, "(DEPRECATED for --skip-auth-route) bypass authentication for requests path's that match (may be given multiple times)")
	flagSet.StringSlice("skip-auth-route", []string{}, "bypass authentication for requests that match the method & path. Format: method=path_regex OR path_regex alone for all methods")
	flagSet.Bool("skip-auth-preflight", false, "will skip authentication for OPTIONS requests")
	flagSet.Bool("skip-auth-strip-headers", false, "strips X-Forwarded-* style authentication headers & Authorization header if they would be set by oauth2-proxy for trusted requests (--skip-auth-route, --skip-auth-regex, --skip-auth-preflight, --trusted-ip)")
	flagSet.StringSlice("trusted-ip", []string{}, "list of IPs or CIDR ranges to allow to bypass authentication. WARNING: trusting by IP has inherent security flaws, read the configuration documentation for more information.")

	return flagSet
}

// authorizationDefaults creates default Authorization options
func authorizationDefaults() Authorization {
	return Authorization{
		TrustedIPs:           nil,
		SkipAuthRegex:        nil,
		SkipAuthRoutes:       nil,
		SkipAuthPreflight:    false,
		SkipAuthStripHeaders: false,
	}
}
