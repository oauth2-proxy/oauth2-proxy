package validation

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt"
	"github.com/mbland/hmacauth"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
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
		for i := range o.Providers {
			if len(o.Providers[i].CAFiles) > 0 {
				caFiles = append(caFiles, o.Providers[i].CAFiles...)
			}
		}

		if len(caFiles) > 0 {
			pool, err := util.GetCertPool(caFiles)
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

func parseProviderInfo(o *options.Options, msgs []string, i int) []string {
	p := &providers.ProviderData{
		Scope:            o.Providers[i].Scope,
		ClientID:         o.Providers[i].ClientID,
		ClientSecret:     o.Providers[i].ClientSecret,
		ClientSecretFile: o.Providers[i].ClientSecretFile,
		Prompt:           o.Providers[i].Prompt,
		ApprovalPrompt:   o.Providers[i].ApprovalPrompt,
		AcrValues:        o.Providers[i].AcrValues,
	}
	p.LoginURL, msgs = parseURL(o.Providers[i].LoginURL, "login", msgs)
	p.RedeemURL, msgs = parseURL(o.Providers[i].RedeemURL, "redeem", msgs)
	p.ProfileURL, msgs = parseURL(o.Providers[i].ProfileURL, "profile", msgs)
	p.ValidateURL, msgs = parseURL(o.Providers[i].ValidateURL, "validate", msgs)
	p.ProtectedResource, msgs = parseURL(o.Providers[i].ProtectedResource, "resource", msgs)

	// Make the OIDC options available to all providers that support it
	p.AllowUnverifiedEmail = o.Providers[i].OIDCConfig.InsecureAllowUnverifiedEmail
	p.EmailClaim = o.Providers[i].OIDCConfig.EmailClaim
	p.GroupsClaim = o.Providers[i].OIDCConfig.GroupsClaim
	p.Verifier = o.GetOIDCVerifier()

	// TODO (@NickMeves) - Remove This
	// Backwards Compatibility for Deprecated UserIDClaim option
	if o.Providers[i].OIDCConfig.EmailClaim == providers.OIDCEmailClaim &&
		o.Providers[i].OIDCConfig.UserIDClaim != providers.OIDCEmailClaim {
		p.EmailClaim = o.Providers[i].OIDCConfig.UserIDClaim
	}

	p.SetAllowedGroups(o.Providers[i].AllowedGroups)

	provider := providers.New(o.Providers[i].Type, p)
	if provider == nil {
		msgs = append(msgs, fmt.Sprintf("invalid setting: provider '%s' is not available", o.Providers[i].Type))
		return msgs
	}
	o.SetProvider(provider)

	switch p := o.GetProvider().(type) {
	case *providers.AzureProvider:
		p.Configure(o.Providers[i].AzureConfig.Tenant)
	case *providers.ADFSProvider:
		p.Configure(o.Providers[i].ADFSConfig.SkipScope)
	case *providers.GitHubProvider:
		p.SetOrgTeam(o.Providers[i].GitHubConfig.Org, o.Providers[i].GitHubConfig.Team)
		p.SetRepo(o.Providers[i].GitHubConfig.Repo, o.Providers[i].GitHubConfig.Token)
		p.SetUsers(o.Providers[i].GitHubConfig.Users)
	case *providers.KeycloakProvider:
		// Backwards compatibility with `--keycloak-group` option
		if len(o.Providers[i].KeycloakConfig.Groups) > 0 {
			p.SetAllowedGroups(o.Providers[i].KeycloakConfig.Groups)
		}
	case *providers.KeycloakOIDCProvider:
		if p.Verifier == nil {
			msgs = append(msgs, "keycloak-oidc provider requires an oidc issuer URL")
		}
		p.AddAllowedRoles(o.Providers[i].KeycloakConfig.Roles)
	case *providers.GoogleProvider:
		if o.Providers[i].GoogleConfig.ServiceAccountJSON != "" {
			file, err := os.Open(o.Providers[i].GoogleConfig.ServiceAccountJSON)
			if err != nil {
				msgs = append(msgs, "invalid Google credentials file: "+o.Providers[i].GoogleConfig.ServiceAccountJSON)
			} else {
				groups := o.Providers[i].AllowedGroups
				// Backwards compatibility with `--google-group` option
				if len(o.Providers[i].GoogleConfig.Groups) > 0 {
					groups = o.Providers[i].GoogleConfig.Groups
					p.SetAllowedGroups(groups)
				}
				p.SetGroupRestriction(groups, o.Providers[i].GoogleConfig.AdminEmail, file)
			}
		}
	case *providers.BitbucketProvider:
		p.SetTeam(o.Providers[i].BitbucketConfig.Team)
		p.SetRepository(o.Providers[i].BitbucketConfig.Repository)
	case *providers.OIDCProvider:
		p.SkipNonce = o.Providers[i].OIDCConfig.InsecureSkipNonce
		if p.Verifier == nil {
			msgs = append(msgs, "oidc provider requires an oidc issuer URL")
		}
	case *providers.GitLabProvider:
		p.SetAllowedGroups(o.Providers[i].GitLabConfig.Group)
		err := p.SetAllowedProjects(o.Providers[i].GitLabConfig.Projects)
		if err != nil {
			msgs = append(msgs, "failed to setup gitlab project access level")
		}

		if p.Verifier == nil {
			// Initialize with default verifier for gitlab.com
			ctx := context.Background()

			provider, err := oidc.NewProvider(ctx, "https://gitlab.com")
			if err != nil {
				msgs = append(msgs, "failed to initialize oidc provider for gitlab.com")
			} else {
				p.Verifier = provider.Verifier(&oidc.Config{
					ClientID: o.Providers[i].ClientID,
				})

				p.LoginURL, msgs = parseURL(provider.Endpoint().AuthURL, "login", msgs)
				p.RedeemURL, msgs = parseURL(provider.Endpoint().TokenURL, "redeem", msgs)
			}
		}
	case *providers.LoginGovProvider:
		p.PubJWKURL, msgs = parseURL(o.Providers[i].LoginGovConfig.PubJWKURL, "pubjwk", msgs)

		// JWT key can be supplied via env variable or file in the filesystem, but not both.
		switch {
		case o.Providers[i].LoginGovConfig.JWTKey != "" && o.Providers[i].LoginGovConfig.JWTKeyFile != "":
			msgs = append(msgs, "cannot set both jwt-key and jwt-key-file options")
		case o.Providers[i].LoginGovConfig.JWTKey == "" && o.Providers[i].LoginGovConfig.JWTKeyFile == "":
			msgs = append(msgs, "login.gov provider requires a private key for signing JWTs")
		case o.Providers[i].LoginGovConfig.JWTKey != "":
			// The JWT Key is in the commandline argument
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(o.Providers[i].LoginGovConfig.JWTKey))
			if err != nil {
				msgs = append(msgs, "could not parse RSA Private Key PEM")
			} else {
				p.JWTKey = signKey
			}
		case o.Providers[i].LoginGovConfig.JWTKeyFile != "":
			// The JWT key is in the filesystem
			keyData, err := ioutil.ReadFile(o.Providers[i].LoginGovConfig.JWTKeyFile)
			if err != nil {
				msgs = append(msgs, "could not read key file: "+o.Providers[i].LoginGovConfig.JWTKeyFile)
			}
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
			if err != nil {
				msgs = append(msgs, "could not parse private key from PEM file:"+o.Providers[i].LoginGovConfig.JWTKeyFile)
			} else {
				p.JWTKey = signKey
			}
		}
	}
	return msgs
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
func newVerifierFromJwtIssuer(jwtIssuer jwtIssuer) (*oidc.IDTokenVerifier, error) {
	config := &oidc.Config{
		ClientID: jwtIssuer.audience,
	}
	// Try as an OpenID Connect Provider first
	var verifier *oidc.IDTokenVerifier
	provider, err := oidc.NewProvider(context.Background(), jwtIssuer.issuerURI)
	if err != nil {
		// Try as JWKS URI
		jwksURI := strings.TrimSuffix(jwtIssuer.issuerURI, "/") + "/.well-known/jwks.json"
		if err := requests.New(jwksURI).Do().Error(); err != nil {
			return nil, err
		}

		verifier = oidc.NewVerifier(jwtIssuer.issuerURI, oidc.NewRemoteKeySet(context.Background(), jwksURI), config)
	} else {
		verifier = provider.Verifier(config)
	}
	return verifier, nil
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
