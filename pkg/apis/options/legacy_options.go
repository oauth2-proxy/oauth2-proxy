package options

import (
	"fmt"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/spf13/pflag"
)

type LegacyOptions struct {
	// Legacy options related to authorization
	LegacyAuthorization LegacyAuthorization `cfg:",squash"`

	// Legacy options related to upstream servers
	LegacyUpstreams LegacyUpstreams `cfg:",squash"`

	Options Options `cfg:",squash"`
}

func NewLegacyOptions() *LegacyOptions {
	return &LegacyOptions{
		LegacyAuthorization: LegacyAuthorization{
			SkipAuthRegex:     nil,
			SkipAuthRoutes:    nil,
			SkipAuthPreflight: false,
			TrustedIPs:        nil,
		},
		LegacyUpstreams: LegacyUpstreams{
			PassHostHeader:  true,
			ProxyWebSockets: true,
			FlushInterval:   time.Duration(1) * time.Second,
		},

		Options: *NewOptions(),
	}
}

func (l *LegacyOptions) ToOptions() (*Options, error) {
	l.Options.RequestAuthZRules = l.LegacyAuthorization.convert()

	upstreams, err := l.LegacyUpstreams.convert()
	if err != nil {
		return nil, fmt.Errorf("error converting upstreams: %v", err)
	}
	l.Options.UpstreamServers = upstreams

	return &l.Options, nil
}

type LegacyUpstreams struct {
	FlushInterval                 time.Duration `flag:"flush-interval" cfg:"flush_interval"`
	PassHostHeader                bool          `flag:"pass-host-header" cfg:"pass_host_header"`
	ProxyWebSockets               bool          `flag:"proxy-websockets" cfg:"proxy_websockets"`
	SSLUpstreamInsecureSkipVerify bool          `flag:"ssl-upstream-insecure-skip-verify" cfg:"ssl_upstream_insecure_skip_verify"`
	Upstreams                     []string      `flag:"upstream" cfg:"upstreams"`
}

func legacyUpstreamsFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("upstreams", pflag.ExitOnError)

	flagSet.Duration("flush-interval", time.Duration(1)*time.Second, "period between response flushing when streaming responses")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Bool("proxy-websockets", true, "enables WebSocket proxying")
	flagSet.Bool("ssl-upstream-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS upstreams")
	flagSet.StringSlice("upstream", []string{}, "the http url(s) of the upstream endpoint, file:// paths for static files or static://<status_code> for static response. Routing is based on the path")

	return flagSet
}

func (l *LegacyUpstreams) convert() (Upstreams, error) {
	upstreams := Upstreams{}

	for _, upstreamString := range l.Upstreams {
		u, err := url.Parse(upstreamString)
		if err != nil {
			return nil, fmt.Errorf("could not parse upstream %q: %v", upstreamString, err)
		}

		if u.Path == "" {
			u.Path = "/"
		}

		upstream := Upstream{
			ID:                    u.Path,
			Path:                  u.Path,
			URI:                   upstreamString,
			InsecureSkipTLSVerify: l.SSLUpstreamInsecureSkipVerify,
			PassHostHeader:        &l.PassHostHeader,
			ProxyWebSockets:       &l.ProxyWebSockets,
			FlushInterval:         &l.FlushInterval,
		}

		switch u.Scheme {
		case "file":
			if u.Fragment != "" {
				upstream.ID = u.Fragment
				upstream.Path = u.Fragment
			}
		case "static":
			responseCode, err := strconv.Atoi(u.Host)
			if err != nil {
				logger.Printf("unable to convert %q to int, use default \"200\"", u.Host)
				responseCode = 200
			}
			upstream.Static = true
			upstream.StaticCode = &responseCode

			// These are not allowed to be empty and must be unique
			upstream.ID = upstreamString
			upstream.Path = upstreamString

			// Force defaults compatible with static responses
			upstream.URI = ""
			upstream.InsecureSkipTLSVerify = false
			upstream.PassHostHeader = nil
			upstream.ProxyWebSockets = nil
			flush := 1 * time.Second
			upstream.FlushInterval = &flush
		}

		upstreams = append(upstreams, upstream)
	}

	return upstreams, nil
}

// LegacyAuthorization holds configuration options related to trusted requests which
// would skip authentication
type LegacyAuthorization struct {
	SkipAuthRegex     []string `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	SkipAuthRoutes    []string `flag:"skip-auth-route" cfg:"skip_auth_routes"`
	SkipAuthPreflight bool     `flag:"skip-auth-preflight" cfg:"skip_auth_preflight"`
	TrustedIPs        []string `flag:"trusted-ip" cfg:"trusted_ips"`
}

// legacyAuthorizationFlagSet creates a new FlagSet with all of the flags required by Authorization
func legacyAuthorizationFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("authorization", pflag.ExitOnError)

	flagSet.StringSlice("skip-auth-regex", []string{}, "(DEPRECATED for --skip-auth-route) bypass authentication for requests path's that match (may be given multiple times)")
	flagSet.StringSlice("skip-auth-route", []string{}, "bypass authentication for requests that match the method & path. Format: method=path_regex OR path_regex alone for all methods")
	flagSet.Bool("skip-auth-preflight", false, "will skip authentication for OPTIONS requests")
	flagSet.StringSlice("trusted-ip", []string{}, "list of IPs or CIDR ranges to allow to bypass authentication. WARNING: trusting by IP has inherent security flaws, read the configuration documentation for more information.")

	return flagSet
}

func (l *LegacyAuthorization) convert() RequestRules {
	var rules RequestRules

	l.convertRoutes(rules)
	l.convertRegexes(rules)
	l.convertPreflight(rules)
	l.convertTrustedIPs(rules)

	return rules
}

func (l *LegacyAuthorization) convertRoutes(rules RequestRules) {
	for i, route := range l.SkipAuthRoutes {
		parts := strings.Split(route, "=")
		if len(parts) == 1 {
			rules = append(rules, RequestRule{
				ID:     fmt.Sprintf("route-%d", i),
				Policy: authorization.AllowPolicy,
				Path:   parts[0],
			})
		} else {
			method := parts[0]
			regex := strings.Join(parts[1:], "=")
			rules = append(rules, RequestRule{
				ID:      fmt.Sprintf("route-%d", i),
				Policy:  authorization.AllowPolicy,
				Path:    regex,
				Methods: []string{method},
			})
		}
	}
}

func (l *LegacyAuthorization) convertRegexes(rules RequestRules) {
	for i, regex := range l.SkipAuthRegex {
		rules = append(rules, RequestRule{
			ID:     fmt.Sprintf("regex-%d", i),
			Policy: authorization.AllowPolicy,
			Path:   regex,
		})
	}
}

func (l *LegacyAuthorization) convertPreflight(rules RequestRules) {
	if l.SkipAuthPreflight {
		rules = append(rules, RequestRule{
			ID:      "preflight",
			Policy:  authorization.AllowPolicy,
			Methods: []string{"OPTIONS"},
		})
	}
}

func (l *LegacyAuthorization) convertTrustedIPs(rules RequestRules) {
	rules = append(rules, RequestRule{
		ID:     "trustedIP",
		Policy: authorization.AllowPolicy,
		IPs:    l.TrustedIPs,
	})
}
