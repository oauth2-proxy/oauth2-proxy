package validation

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/mbland/hmacauth"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
)

// Validate checks that required options are set and validates those that they
// are of the correct format
func Validate(o *options.Options) error {
	msgs := validateCookie(o.Cookie)
	msgs = append(msgs, validateSessionCookieMinimal(o)...)
	msgs = append(msgs, validateRedisSessionStore(o)...)
	msgs = append(msgs, prefixValues("injectRequestHeaders: ", validateHeaders(o.InjectRequestHeaders)...)...)
	msgs = append(msgs, prefixValues("injectResponseHeaders: ", validateHeaders(o.InjectResponseHeaders)...)...)
	msgs = append(msgs, validateProviders(o)...)
	msgs = configureLogger(o.Logging, msgs)
	msgs = parseSignatureKey(o, msgs)

	if o.SSLInsecureSkipVerify {
		// InsecureSkipVerify is a configurable option we allow
		/* #nosec G402 */
		insecureTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.DefaultClient = &http.Client{Transport: insecureTransport}
	} else {
		caFiles := make([]string, 0)
		defaultCAPoolNeeded := false

		for i := range o.Providers {
			if len(o.Providers[i].CAFiles) > 0 {
				caFiles = append(caFiles, o.Providers[i].CAFiles...)
			} else {
				defaultCAPoolNeeded = true
			}
		}

		if len(caFiles) > 0 {
			pool, err := util.GetCertPool(caFiles, defaultCAPoolNeeded)
			if err == nil {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.TLSClientConfig = &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS12,
				}
				http.DefaultClient = &http.Client{Transport: transport}
			} else {
				msgs = append(msgs, fmt.Sprintf("unable to load provider CA file(s): %v", err))
			}
		}
	}

	if o.AuthenticatedEmailsFile == "" && len(o.EmailDomains) == 0 && o.HtpasswdFile == "" {
		msgs = append(msgs, "missing setting for email validation: email-domain or authenticated-emails-file required."+
			"\n      use email-domain=* to authorize all email addresses")
	}

	if o.SkipJwtBearerTokens {
		// Configure extra issuers
		if len(o.ExtraJwtIssuers) > 0 {
			var jwtIssuers []jwtIssuer
			jwtIssuers, msgs = parseJwtIssuers(o.ExtraJwtIssuers, msgs)
			for _, jwtIssuer := range jwtIssuers {
				verifier, err := newVerifierFromJwtIssuer(
					o.Providers[0].OIDCConfig.AudienceClaims,
					o.Providers[0].OIDCConfig.ExtraAudiences,
					jwtIssuer,
				)
				if err != nil {
					msgs = append(msgs, fmt.Sprintf("error building verifiers: %s", err))
				}
				o.SetJWTBearerVerifiers(append(o.GetJWTBearerVerifiers(), verifier))
			}
	o = o.InitProviders()

	//Temporary fix to allow a provider without a name in the default config
	//TODO remove once legacy config is removed from the project

	if o.Providers[0].Name == "" {
		o.Providers[0].Name = o.Providers[0].Type
	}

	for i := range o.Providers {
		if o.Providers[i].OIDCConfig.IssuerURL != "" {

			ctx := context.Background()

			if o.Providers[i].OIDCConfig.InsecureSkipIssuerVerification && !o.Providers[i].OIDCConfig.SkipDiscovery {
				// go-oidc doesn't let us pass bypass the issuer check this in the oidc.NewProvider call
				// (which uses discovery to get the URLs), so we'll do a quick check ourselves and if
				// we get the URLs, we'll just use the non-discovery path.

				logger.Printf("Performing OIDC Discovery for %v", o.Providers[i].Type)

				requestURL := strings.TrimSuffix(o.Providers[i].OIDCConfig.IssuerURL, "/") + "/.well-known/openid-configuration"
				body, err := requests.New(requestURL).
					WithContext(ctx).
					Do().
					UnmarshalJSON()
				if err != nil {
					logger.Errorf("error: failed to discover OIDC configuration: %v", err)
				} else {
					// Prefer manually configured URLs. It's a bit unclear
					// why you'd be doing discovery and also providing the URLs
					// explicitly though...
					if o.Providers[i].LoginURL == "" {
						o.Providers[i].LoginURL = body.Get("authorization_endpoint").MustString()
					}

					if o.Providers[i].RedeemURL == "" {
						o.Providers[i].RedeemURL = body.Get("token_endpoint").MustString()
					}

					if o.Providers[i].OIDCConfig.JwksURL == "" {
						o.Providers[i].OIDCConfig.JwksURL = body.Get("jwks_uri").MustString()
					}

					if o.Providers[i].ProfileURL == "" {
						o.Providers[i].ProfileURL = body.Get("userinfo_endpoint").MustString()
					}

					o.Providers[i].OIDCConfig.SkipDiscovery = true
				}
			}

			// Construct a manual IDTokenVerifier from issuer URL & JWKS URI
			// instead of metadata discovery if we enable -skip-oidc-discovery.
			// In this case we need to make sure the required endpoints for
			// the provider are configured.
			if o.Providers[i].OIDCConfig.SkipDiscovery {
				if o.Providers[i].LoginURL == "" {
					msgs = append(msgs, "missing setting: login-url")
				}
				if o.Providers[i].RedeemURL == "" {
					msgs = append(msgs, "missing setting: redeem-url")
				}
				if o.Providers[i].OIDCConfig.JwksURL == "" {
					msgs = append(msgs, "missing setting: oidc-jwks-url")
				}
				keySet := oidc.NewRemoteKeySet(ctx, o.Providers[i].OIDCConfig.JwksURL)
				o.SetOIDCVerifier(oidc.NewVerifier(o.Providers[i].OIDCConfig.IssuerURL, keySet, &oidc.Config{
					ClientID:        o.Providers[i].ClientID,
					SkipIssuerCheck: o.Providers[i].OIDCConfig.InsecureSkipIssuerVerification,
				}))
			} else {
				// Configure discoverable provider data.
				provider, err := oidc.NewProvider(ctx, o.Providers[i].OIDCConfig.IssuerURL)
				if err != nil {
					return err
				}
				o.SetOIDCVerifier(provider.Verifier(&oidc.Config{
					ClientID:        o.Providers[i].ClientID,
					SkipIssuerCheck: o.Providers[i].OIDCConfig.InsecureSkipIssuerVerification,
				}))

				o.Providers[i].LoginURL = provider.Endpoint().AuthURL
				o.Providers[i].RedeemURL = provider.Endpoint().TokenURL
			}
			if o.Providers[i].Scope == "" {
				o.Providers[i].Scope = "openid email profile"

				if len(o.Providers[i].AllowedGroups) > 0 {
					o.Providers[i].Scope += " groups"
				}
			}
			if o.Providers[i].OIDCConfig.UserIDClaim == "" {
				o.Providers[i].OIDCConfig.UserIDClaim = "email"
			}
		}

		if o.SkipJwtBearerTokens {
			// Configure extra issuers
			if len(o.ExtraJwtIssuers) > 0 {
				var jwtIssuers []jwtIssuer
				jwtIssuers, msgs = parseJwtIssuers(o.ExtraJwtIssuers, msgs)
				for _, jwtIssuer := range jwtIssuers {
					verifier, err := newVerifierFromJwtIssuer(jwtIssuer)
					if err != nil {
						msgs = append(msgs, fmt.Sprintf("error building verifiers: %s", err))
					}
					o.SetJWTBearerVerifiers(append(o.GetJWTBearerVerifiers(), verifier))
				}
			}
		}

		var redirectURL *url.URL
		redirectURL, msgs = parseURL(o.RawRedirectURL, "redirect", msgs)
		o.SetRedirectURL(redirectURL)
		if o.RawRedirectURL == "" && !o.Cookie.Secure && !o.ReverseProxy {
			logger.Print("WARNING: no explicit redirect URL: redirects will default to insecure HTTP")
		}

		msgs = append(msgs, validateUpstreams(o.UpstreamServers)...)
		msgs = parseProviderInfo(o, msgs, i)
	}

	o.SetProviderMap()

	if o.ReverseProxy {
		parser, err := ip.GetRealClientIPParser(o.RealClientIPHeader)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("real_client_ip_header (%s) not accepted parameter value: %v", o.RealClientIPHeader, err))
		}
		o.SetRealClientIPParser(parser)

		// Allow the logger to get client IPs
		logger.SetGetClientFunc(func(r *http.Request) string {
			return ip.GetClientString(o.GetRealClientIPParser(), r, false)
		})
	}

	// Do this after ReverseProxy validation for TrustedIP coordinated checks
	msgs = append(msgs, validateAllowlists(o)...)

	if len(msgs) != 0 {
		return fmt.Errorf("invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseSignatureKey(o *options.Options, msgs []string) []string {
	if o.SignatureKey == "" {
		return msgs
	}

	logger.Print("WARNING: `--signature-key` is deprecated. It will be removed in a future release")

	components := strings.Split(o.SignatureKey, ":")
	if len(components) != 2 {
		return append(msgs, "invalid signature hash:key spec: "+
			o.SignatureKey)
	}

	algorithm, secretKey := components[0], components[1]
	hash, err := hmacauth.DigestNameToCryptoHash(algorithm)
	if err != nil {
		return append(msgs, "unsupported signature hash algorithm: "+o.SignatureKey)
	}
	o.SetSignatureData(&options.SignatureData{Hash: hash, Key: secretKey})
	return msgs
}

// parseJwtIssuers takes in an array of strings in the form of issuer=audience
// and parses to an array of jwtIssuer structs.
func parseJwtIssuers(issuers []string, msgs []string) ([]jwtIssuer, []string) {
	parsedIssuers := make([]jwtIssuer, 0, len(issuers))
	for _, jwtVerifier := range issuers {
		components := strings.Split(jwtVerifier, "=")
		if len(components) < 2 {
			msgs = append(msgs, fmt.Sprintf("invalid jwt verifier uri=audience spec: %s", jwtVerifier))
			continue
		}
		uri, audience := components[0], strings.Join(components[1:], "=")
		parsedIssuers = append(parsedIssuers, jwtIssuer{issuerURI: uri, audience: audience})
	}
	return parsedIssuers, msgs
}

// newVerifierFromJwtIssuer takes in issuer information in jwtIssuer info and returns
// a verifier for that issuer.
func newVerifierFromJwtIssuer(audienceClaims []string, extraAudiences []string, jwtIssuer jwtIssuer) (internaloidc.IDTokenVerifier, error) {
	pvOpts := internaloidc.ProviderVerifierOptions{
		AudienceClaims: audienceClaims,
		ClientID:       jwtIssuer.audience,
		ExtraAudiences: extraAudiences,
		IssuerURL:      jwtIssuer.issuerURI,
	}

	pv, err := internaloidc.NewProviderVerifier(context.TODO(), pvOpts)
	if err != nil {
		// If the discovery didn't work, try again without discovery
		pvOpts.JWKsURL = strings.TrimSuffix(jwtIssuer.issuerURI, "/") + "/.well-known/jwks.json"
		pvOpts.SkipDiscovery = true

		pv, err = internaloidc.NewProviderVerifier(context.TODO(), pvOpts)
		if err != nil {
			return nil, fmt.Errorf("could not construct provider verifier for JWT Issuer: %v", err)
		}
	}

	return pv.Verifier(), nil
}

// jwtIssuer hold parsed JWT issuer info that's used to construct a verifier.
type jwtIssuer struct {
	issuerURI string
	audience  string
}

func parseURL(toParse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(toParse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, toParse, err))
	}
	return parsed, msgs
}
