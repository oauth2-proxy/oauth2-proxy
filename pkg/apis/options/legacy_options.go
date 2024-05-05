package options

import (
	"fmt"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/spf13/pflag"
)

type LegacyOptions struct {
	// Legacy options for the overall proxy behaviour
	LegacyProxyOptions LegacyProxyOptions `cfg:",squash"`

	// Legacy options related to upstream servers
	LegacyUpstreams LegacyUpstreams `cfg:",squash"`

	// Legacy options for injecting request/response headers
	LegacyHeaders LegacyHeaders `cfg:",squash"`

	// Legacy options for the server address and TLS
	LegacyServer LegacyServer `cfg:",squash"`

	// Legacy options for single provider
	LegacyProvider LegacyProvider `cfg:",squash"`

	// Legacy options for cookies
	LegacyCookie LegacyCookie `cfg:",squash"`

	// Legacy options for probing oauth2-proxy
	LegacyProbeOptions LegacyProbeOptions `cfg:",squash"`

	// Legacy options for configuring the sign in and error pages
	LegacyPageTemplates LegacyPageTemplates `cfg:",squash"`

	// Legacy options for configuring the cookie session storage
	LegacySessionOptions LegacySessionOptions `cfg:",squash"`

	// Legacy options for logging
	LegacyLogging LegacyLogging `cfg:",squash"`
}

func NewLegacyOptions() *LegacyOptions {
	return &LegacyOptions{
		LegacyProxyOptions: LegacyProxyOptions{
			ProxyPrefix:        "/oauth2",
			RealClientIPHeader: "X-Real-IP",
			ForceHTTPS:         false,
			SkipAuthPreflight:  false,
		},

		LegacyUpstreams: LegacyUpstreams{
			PassHostHeader:  true,
			ProxyWebSockets: true,
			FlushInterval:   DefaultUpstreamFlushInterval,
			Timeout:         DefaultUpstreamTimeout,
		},

		LegacyHeaders: LegacyHeaders{
			PassBasicAuth:        true,
			PassUserHeaders:      true,
			SkipAuthStripHeaders: true,
		},

		LegacyServer: LegacyServer{
			HTTPAddress:  "127.0.0.1:4180",
			HTTPSAddress: ":443",
		},

		LegacyProvider: LegacyProvider{
			ProviderType:          "google",
			AzureTenant:           "common",
			ApprovalPrompt:        "force",
			UserIDClaim:           "email",
			OIDCEmailClaim:        "email",
			OIDCGroupsClaim:       "groups",
			OIDCAudienceClaims:    []string{"aud"},
			OIDCExtraAudiences:    []string{},
			InsecureOIDCSkipNonce: true,
		},

		LegacyCookie: LegacyCookie{
			Name:           "_oauth2_proxy",
			Secret:         "",
			Domains:        nil,
			Path:           "/",
			Expire:         time.Duration(168) * time.Hour,
			Refresh:        time.Duration(0),
			Secure:         true,
			HTTPOnly:       true,
			SameSite:       "",
			CSRFPerRequest: false,
			CSRFExpire:     time.Duration(15) * time.Minute,
		},

		LegacyProbeOptions: LegacyProbeOptions{
			PingPath:      "/ping",
			PingUserAgent: "",
			ReadyPath:     "/ready",
		},

		LegacyPageTemplates: LegacyPageTemplates{
			DisplayLoginForm: true,
		},

		LegacySessionOptions: LegacySessionOptions{
			Type: "cookie",
			Cookie: LegacyCookieStoreOptions{
				Minimal: false,
			},
		},

		LegacyLogging: LegacyLogging{
			ExcludePaths:    nil,
			LocalTime:       true,
			SilencePing:     false,
			RequestIDHeader: "X-Request-Id",
			AuthEnabled:     true,
			AuthFormat:      logger.DefaultAuthLoggingFormat,
			RequestEnabled:  true,
			RequestFormat:   logger.DefaultRequestLoggingFormat,
			StandardEnabled: true,
			StandardFormat:  logger.DefaultStandardLoggingFormat,
			ErrToInfo:       false,
			File: LegacyLogFileOptions{
				Filename:   "",
				MaxSize:    100,
				MaxAge:     7,
				MaxBackups: 0,
				Compress:   false,
			},
		},
	}
}

func NewLegacyFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ExitOnError)

	flagSet.AddFlagSet(legacyProxyOptionsFlagSet())
	flagSet.AddFlagSet(legacyUpstreamsFlagSet())
	flagSet.AddFlagSet(legacyHeadersFlagSet())
	flagSet.AddFlagSet(legacyServerFlagset())
	flagSet.AddFlagSet(legacyProviderFlagSet())
	flagSet.AddFlagSet(legacyGoogleFlagSet())
	flagSet.AddFlagSet(legacyCookieFlagSet())
	flagSet.AddFlagSet(legacyProbeOptionsFlagSet())
	flagSet.AddFlagSet(legacyPageTemplatesFlagSet())
	flagSet.AddFlagSet(legacySessionFlagSet())
	flagSet.AddFlagSet(legacyLoggingFlagSet())

	return flagSet
}

func (l *LegacyOptions) ToOptions() (*Options, error) {
	opts := NewOptions()
	opts.ProxyOptions = l.LegacyProxyOptions.convert()

	upstreams, err := l.LegacyUpstreams.convert()
	if err != nil {
		return nil, fmt.Errorf("error converting upstreams: %v", err)
	}

	opts.UpstreamServers = upstreams
	opts.InjectRequestHeaders, opts.InjectResponseHeaders = l.LegacyHeaders.convert()
	opts.Server, opts.MetricsServer = l.LegacyServer.convert()
	opts.LegacyPreferEmailToUser = l.LegacyHeaders.PreferEmailToUser

	providers, err := l.LegacyProvider.convert()
	if err != nil {
		return nil, fmt.Errorf("error converting provider: %v", err)
	}

	opts.Providers = providers
	opts.Cookie = l.LegacyCookie.convert()
	opts.ProbeOptions = l.LegacyProbeOptions.convert()
	opts.PageTemplates = l.LegacyPageTemplates.convert()
	opts.Session = l.LegacySessionOptions.convert()
	opts.Logging = l.LegacyLogging.convert()

	return opts, nil
}
