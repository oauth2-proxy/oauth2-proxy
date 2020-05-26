package options

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

type LegacyOptions struct {
	// Legacy options related to upstream servers
	LegacyFlushInterval                 time.Duration `flag:"flush-interval" cfg:"flush_interval"`
	LegacyPassHostHeader                bool          `flag:"pass-host-header" cfg:"pass_host_header"`
	LegacyProxyWebSockets               bool          `flag:"proxy-websockets" cfg:"proxy_websockets"`
	LegacySSLUpstreamInsecureSkipVerify bool          `flag:"ssl-upstream-insecure-skip-verify" cfg:"ssl_upstream_insecure_skip_verify"`
	LegacyUpstreams                     []string      `flag:"upstream" cfg:"upstreams"`

	Options Options `cfg:",squash"`
}

func NewLegacyOptions() *LegacyOptions {
	return &LegacyOptions{
		LegacyPassHostHeader:  true,
		LegacyProxyWebSockets: true,
		LegacyFlushInterval:   time.Duration(1) * time.Second,

		Options: *NewOptions(),
	}
}

func (l *LegacyOptions) ToOptions() (*Options, error) {
	upstreams, err := convertLegacyUpstreams(l.LegacyUpstreams, l.LegacySSLUpstreamInsecureSkipVerify, l.LegacyPassHostHeader, l.LegacyProxyWebSockets, l.LegacyFlushInterval)
	if err != nil {
		return nil, fmt.Errorf("error converting upstreams: %v", err)
	}
	l.Options.UpstreamServers = upstreams

	return &l.Options, nil
}

func convertLegacyUpstreams(upstreamStrings []string, skipVerify, passHostHeader, proxyWebSockets bool, flushInterval time.Duration) (Upstreams, error) {
	upstreams := Upstreams{}

	for _, upstreamString := range upstreamStrings {
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
			InsecureSkipTLSVerify: skipVerify,
			PassHostHeader:        passHostHeader,
			ProxyWebSockets:       proxyWebSockets,
			FlushInterval:         &flushInterval,
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
			upstream.PassHostHeader = true
			upstream.ProxyWebSockets = false
			flush := 1 * time.Second
			upstream.FlushInterval = &flush
		}

		upstreams = append(upstreams, upstream)
	}

	return upstreams, nil
}
