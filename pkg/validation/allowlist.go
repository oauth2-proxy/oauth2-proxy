package validation

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
)

func validateAllowlists(o *options.Options) []string {
	msgs := []string{}

	msgs = append(msgs, validateRoutes(o)...)
	msgs = append(msgs, validateRegexes(o)...)
	msgs = append(msgs, validateTrustedIPs(o)...)

	if len(o.TrustedIPs) > 0 && o.ReverseProxy {
		_, err := fmt.Fprintln(os.Stderr, "WARNING: mixing --trusted-ip with --reverse-proxy is a potential security vulnerability. An attacker can inject a trusted IP into an X-Real-IP or X-Forwarded-For header if they aren't properly protected outside of oauth2-proxy")
		if err != nil {
			panic(err)
		}
	}

	return msgs
}

// validateRoutes validates method=path routes passed with options.SkipAuthRoutes
func validateRoutes(o *options.Options) []string {
	msgs := []string{}
	for _, route := range o.SkipAuthRoutes {
		var regex string
		parts := strings.SplitN(route, "=", 2)
		if len(parts) == 1 {
			regex = parts[0]
		} else {
			regex = parts[1]
		}
		_, err := regexp.Compile(regex)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error compiling regex /%s/: %v", regex, err))
		}
	}
	return msgs
}

// validateRegex validates regex paths passed with options.SkipAuthRegex
func validateRegexes(o *options.Options) []string {
	msgs := []string{}
	for _, regex := range o.SkipAuthRegex {
		_, err := regexp.Compile(regex)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error compiling regex /%s/: %v", regex, err))
		}
	}
	return msgs
}

// validateTrustedIPs validates IP/CIDRs for IP based allowlists
func validateTrustedIPs(o *options.Options) []string {
	msgs := []string{}
	for i, ipStr := range o.TrustedIPs {
		if nil == ip.ParseIPNet(ipStr) {
			msgs = append(msgs, fmt.Sprintf("trusted_ips[%d] (%s) could not be recognized", i, ipStr))
		}
	}
	return msgs
}
