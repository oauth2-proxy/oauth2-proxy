package options

import (
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/spf13/pflag"
)

type LegacyAuthorization struct {
	SkipAuthRegex     []string `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	SkipAuthRoutes    []string `flag:"skip-auth-route" cfg:"skip_auth_routes"`
	SkipAuthPreflight bool     `flag:"skip-auth-preflight" cfg:"skip_auth_preflight"`
	TrustedIPs        []string `flag:"trusted-ip" cfg:"trusted_ips"`
}

func legacyAuthorizationFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("authorization", pflag.ExitOnError)

	return flagSet
}

func (l *LegacyAuthorization) convert() Authorization {
	auth := Authorization{}

	if l.SkipAuthPreflight {
		auth.RequestRules = append(auth.RequestRules, AuthorizationRule{
			ID:      "skip-auth-preflight",
			Methods: []string{"OPTIONS"},
		})
	}

	auth.RequestRules = append(auth.RequestRules, convertSkipAuthRegex(l.SkipAuthRegex)...)
	auth.RequestRules = append(auth.RequestRules, convertSkipAuthRoutes(l.SkipAuthRoutes)...)

	if len(l.TrustedIPs) > 0 {
		auth.RequestRules = append(auth.RequestRules, AuthorizationRule{
			ID:     "trusted-ips",
			Policy: AllowPolicy,
			IPs:    l.TrustedIPs,
		})
	}

	return auth
}

func convertSkipAuthRegex(regexes []string) []AuthorizationRule {
	rules := []AuthorizationRule{}

	for _, regex := range regexes {
		logger.Printf("Skipping auth - Method: ALL | Path: %s", regex)
		rules = append(rules, AuthorizationRule{
			ID:   regex,
			Path: regex,
		})
	}

	return rules
}

func convertSkipAuthRoutes(routes []string) []AuthorizationRule {
	rules := []AuthorizationRule{}

	for _, route := range routes {
		method, path := splitMethodPath(route)
		logger.Printf("Skipping auth - Method: %s | Path: %s", method, path)
		rules = append(rules, AuthorizationRule{
			ID:      route,
			Path:    path,
			Methods: []string{method},
		})
	}

	return rules
}

func splitMethodPath(methodPath string) (string, string) {
	parts := strings.SplitN(methodPath, "=", 2)
	if len(parts) == 1 {
		return "", parts[0]
	}
	return strings.ToUpper(parts[0]), parts[1]
}
