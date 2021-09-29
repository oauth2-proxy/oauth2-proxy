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
	} else if len(o.Providers[0].CAFiles) > 0 {
		pool, err := util.GetCertPool(o.Providers[0].CAFiles)
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

	if o.AuthenticatedEmailsFile == "" && len(o.EmailDomains) == 0 && o.HtpasswdFile == "" {
		msgs = append(msgs, "missing setting for email validation: email-domain or authenticated-emails-file required."+
			"\n      use email-domain=* to authorize all email addresses")
	}

	if o.Providers[0].OIDCConfig.IssuerURL != "" {

		ctx := context.Background()

		if o.Providers[0].OIDCConfig.InsecureSkipIssuerVerification && !o.Providers[0].OIDCConfig.SkipDiscovery {
			// go-oidc doesn't let us pass bypass the issuer check this in the oidc.NewProvider call
			// (which uses discovery to get the URLs), so we'll do a quick check ourselves and if
			// we get the URLs, we'll just use the non-discovery path.

			logger.Printf("Performing OIDC Discovery...")

			requestURL := strings.TrimSuffix(o.Providers[0].OIDCConfig.IssuerURL, "/") + "/.well-known/openid-configuration"
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
				if o.Providers[0].LoginURL == "" {
					o.Providers[0].LoginURL = body.Get("authorization_endpoint").MustString()
				}

				if o.Providers[0].RedeemURL == "" {
					o.Providers[0].RedeemURL = body.Get("token_endpoint").MustString()
				}

				if o.Providers[0].OIDCConfig.JwksURL == "" {
					o.Providers[0].OIDCConfig.JwksURL = body.Get("jwks_uri").MustString()
				}

				if o.Providers[0].ProfileURL == "" {
					o.Providers[0].ProfileURL = body.Get("userinfo_endpoint").MustString()
				}

				o.Providers[0].OIDCConfig.SkipDiscovery = true
			}
		}

		// Construct a manual IDTokenVerifier from issuer URL & JWKS URI
		// instead of metadata discovery if we enable -skip-oidc-discovery.
		// In this case we need to make sure the required endpoints for
		// the provider are configured.
		if o.Providers[0].OIDCConfig.SkipDiscovery {
			if o.Providers[0].LoginURL == "" {
				msgs = append(msgs, "missing setting: login-url")
			}
			if o.Providers[0].RedeemURL == "" {
				msgs = append(msgs, "missing setting: redeem-url")
			}
			if o.Providers[0].OIDCConfig.JwksURL == "" {
				msgs = append(msgs, "missing setting: oidc-jwks-url")
			}
			keySet := oidc.NewRemoteKeySet(ctx, o.Providers[0].OIDCConfig.JwksURL)
			o.SetOIDCVerifier(oidc.NewVerifier(o.Providers[0].OIDCConfig.IssuerURL, keySet, &oidc.Config{
				ClientID:        o.Providers[0].ClientID,
				SkipIssuerCheck: o.Providers[0].OIDCConfig.InsecureSkipIssuerVerification,
			}))
		} else {
			// Configure discoverable provider data.
			provider, err := oidc.NewProvider(ctx, o.Providers[0].OIDCConfig.IssuerURL)
			if err != nil {
				return err
			}
			o.SetOIDCVerifier(provider.Verifier(&oidc.Config{
				ClientID:        o.Providers[0].ClientID,
				SkipIssuerCheck: o.Providers[0].OIDCConfig.InsecureSkipIssuerVerification,
			}))

			o.Providers[0].LoginURL = provider.Endpoint().AuthURL
			o.Providers[0].RedeemURL = provider.Endpoint().TokenURL
		}
		if o.Providers[0].Scope == "" {
			o.Providers[0].Scope = "openid email profile"

			if len(o.Providers[0].AllowedGroups) > 0 {
				o.Providers[0].Scope += " groups"
			}
		}
		if o.Providers[0].OIDCConfig.UserIDClaim == "" {
			o.Providers[0].OIDCConfig.UserIDClaim = "email"
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
	msgs = parseProviderInfo(o, msgs)

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

func parseProviderInfo(o *options.Options, msgs []string) []string {
	p := &providers.ProviderData{
		Scope:            o.Providers[0].Scope,
		ClientID:         o.Providers[0].ClientID,
		ClientSecret:     o.Providers[0].ClientSecret,
		ClientSecretFile: o.Providers[0].ClientSecretFile,
		Prompt:           o.Providers[0].Prompt,
		ApprovalPrompt:   o.Providers[0].ApprovalPrompt,
		AcrValues:        o.Providers[0].AcrValues,
	}
	p.LoginURL, msgs = parseURL(o.Providers[0].LoginURL, "login", msgs)
	p.RedeemURL, msgs = parseURL(o.Providers[0].RedeemURL, "redeem", msgs)
	p.ProfileURL, msgs = parseURL(o.Providers[0].ProfileURL, "profile", msgs)
	p.ValidateURL, msgs = parseURL(o.Providers[0].ValidateURL, "validate", msgs)
	p.ProtectedResource, msgs = parseURL(o.Providers[0].ProtectedResource, "resource", msgs)

	// Make the OIDC options available to all providers that support it
	p.AllowUnverifiedEmail = o.Providers[0].OIDCConfig.InsecureAllowUnverifiedEmail
	p.EmailClaim = o.Providers[0].OIDCConfig.EmailClaim
	p.GroupsClaim = o.Providers[0].OIDCConfig.GroupsClaim
	p.Verifier = o.GetOIDCVerifier()

	// TODO (@NickMeves) - Remove This
	// Backwards Compatibility for Deprecated UserIDClaim option
	if o.Providers[0].OIDCConfig.EmailClaim == providers.OIDCEmailClaim &&
		o.Providers[0].OIDCConfig.UserIDClaim != providers.OIDCEmailClaim {
		p.EmailClaim = o.Providers[0].OIDCConfig.UserIDClaim
	}

	p.SetAllowedGroups(o.Providers[0].AllowedGroups)

	provider := providers.New(o.Providers[0].Type, p)
	if provider == nil {
		msgs = append(msgs, fmt.Sprintf("invalid setting: provider '%s' is not available", o.Providers[0].Type))
		return msgs
	}
	o.SetProvider(provider)

	switch p := o.GetProvider().(type) {
	case *providers.AzureProvider:
		p.Configure(o.Providers[0].AzureConfig.Tenant)
	case *providers.ADFSProvider:
		p.Configure(o.Providers[0].ADFSConfig.SkipScope)
	case *providers.GitHubProvider:
		p.SetOrgTeam(o.Providers[0].GitHubConfig.Org, o.Providers[0].GitHubConfig.Team)
		p.SetRepo(o.Providers[0].GitHubConfig.Repo, o.Providers[0].GitHubConfig.Token)
		p.SetUsers(o.Providers[0].GitHubConfig.Users)
	case *providers.KeycloakProvider:
		// Backwards compatibility with `--keycloak-group` option
		if len(o.Providers[0].KeycloakConfig.Groups) > 0 {
			p.SetAllowedGroups(o.Providers[0].KeycloakConfig.Groups)
		}
	case *providers.KeycloakOIDCProvider:
		if p.Verifier == nil {
			msgs = append(msgs, "keycloak-oidc provider requires an oidc issuer URL")
		}
		p.AddAllowedRoles(o.Providers[0].KeycloakConfig.Roles)
	case *providers.GoogleProvider:
		if o.Providers[0].GoogleConfig.ServiceAccountJSON != "" {
			file, err := os.Open(o.Providers[0].GoogleConfig.ServiceAccountJSON)
			if err != nil {
				msgs = append(msgs, "invalid Google credentials file: "+o.Providers[0].GoogleConfig.ServiceAccountJSON)
			} else {
				groups := o.Providers[0].AllowedGroups
				// Backwards compatibility with `--google-group` option
				if len(o.Providers[0].GoogleConfig.Groups) > 0 {
					groups = o.Providers[0].GoogleConfig.Groups
					p.SetAllowedGroups(groups)
				}
				p.SetGroupRestriction(groups, o.Providers[0].GoogleConfig.AdminEmail, file)
			}
		}
	case *providers.BitbucketProvider:
		p.SetTeam(o.Providers[0].BitbucketConfig.Team)
		p.SetRepository(o.Providers[0].BitbucketConfig.Repository)
	case *providers.OIDCProvider:
		p.SkipNonce = o.Providers[0].OIDCConfig.InsecureSkipNonce
		if p.Verifier == nil {
			msgs = append(msgs, "oidc provider requires an oidc issuer URL")
		}
	case *providers.GitLabProvider:
		p.SetAllowedGroups(o.Providers[0].GitLabConfig.Group)
		err := p.SetAllowedProjects(o.Providers[0].GitLabConfig.Projects)
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
					ClientID: o.Providers[0].ClientID,
				})

				p.LoginURL, msgs = parseURL(provider.Endpoint().AuthURL, "login", msgs)
				p.RedeemURL, msgs = parseURL(provider.Endpoint().TokenURL, "redeem", msgs)
			}
		}
	case *providers.LoginGovProvider:
		p.PubJWKURL, msgs = parseURL(o.Providers[0].LoginGovConfig.PubJWKURL, "pubjwk", msgs)

		// JWT key can be supplied via env variable or file in the filesystem, but not both.
		switch {
		case o.Providers[0].LoginGovConfig.JWTKey != "" && o.Providers[0].LoginGovConfig.JWTKeyFile != "":
			msgs = append(msgs, "cannot set both jwt-key and jwt-key-file options")
		case o.Providers[0].LoginGovConfig.JWTKey == "" && o.Providers[0].LoginGovConfig.JWTKeyFile == "":
			msgs = append(msgs, "login.gov provider requires a private key for signing JWTs")
		case o.Providers[0].LoginGovConfig.JWTKey != "":
			// The JWT Key is in the commandline argument
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(o.Providers[0].LoginGovConfig.JWTKey))
			if err != nil {
				msgs = append(msgs, "could not parse RSA Private Key PEM")
			} else {
				p.JWTKey = signKey
			}
		case o.Providers[0].LoginGovConfig.JWTKeyFile != "":
			// The JWT key is in the filesystem
			keyData, err := ioutil.ReadFile(o.Providers[0].LoginGovConfig.JWTKeyFile)
			if err != nil {
				msgs = append(msgs, "could not read key file: "+o.Providers[0].LoginGovConfig.JWTKeyFile)
			}
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
			if err != nil {
				msgs = append(msgs, "could not parse private key from PEM file:"+o.Providers[0].LoginGovConfig.JWTKeyFile)
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
