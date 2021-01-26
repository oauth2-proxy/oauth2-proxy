package validation

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
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

	if o.SSLInsecureSkipVerify {
		// InsecureSkipVerify is a configurable option we allow
		/* #nosec G402 */
		insecureTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.DefaultClient = &http.Client{Transport: insecureTransport}
	} else if len(o.ProviderCAFiles) > 0 {
		pool, err := util.GetCertPool(o.ProviderCAFiles)
		if err == nil {
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			}

			http.DefaultClient = &http.Client{Transport: transport}
		} else {
			msgs = append(msgs, fmt.Sprintf("unable to load provider CA file(s): %v", err))
		}
	}

	if o.ClientID == "" {
		msgs = append(msgs, "missing setting: client-id")
	}
	// login.gov uses a signed JWT to authenticate, not a client-secret
	if o.ProviderType != "login.gov" {
		if o.ClientSecret == "" && o.ClientSecretFile == "" {
			msgs = append(msgs, "missing setting: client-secret or client-secret-file")
		}
		if o.ClientSecret == "" && o.ClientSecretFile != "" {
			_, err := ioutil.ReadFile(o.ClientSecretFile)
			if err != nil {
				msgs = append(msgs, "could not read client secret file: "+o.ClientSecretFile)
			}
		}
	}
	if o.AuthenticatedEmailsFile == "" && len(o.EmailDomains) == 0 && o.HtpasswdFile == "" {
		msgs = append(msgs, "missing setting for email validation: email-domain or authenticated-emails-file required."+
			"\n      use email-domain=* to authorize all email addresses")
	}

	if o.OIDCIssuerURL != "" {

		ctx := context.Background()

		if o.InsecureOIDCSkipIssuerVerification && !o.SkipOIDCDiscovery {
			// go-oidc doesn't let us pass bypass the issuer check this in the oidc.NewProvider call
			// (which uses discovery to get the URLs), so we'll do a quick check ourselves and if
			// we get the URLs, we'll just use the non-discovery path.

			logger.Printf("Performing OIDC Discovery...")

			requestURL := strings.TrimSuffix(o.OIDCIssuerURL, "/") + "/.well-known/openid-configuration"
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
				if o.LoginURL == "" {
					o.LoginURL = body.Get("authorization_endpoint").MustString()
				}

				if o.RedeemURL == "" {
					o.RedeemURL = body.Get("token_endpoint").MustString()
				}

				if o.OIDCJwksURL == "" {
					o.OIDCJwksURL = body.Get("jwks_uri").MustString()
				}

				if o.ProfileURL == "" {
					o.ProfileURL = body.Get("userinfo_endpoint").MustString()
				}

				o.SkipOIDCDiscovery = true
			}
		}

		// Construct a manual IDTokenVerifier from issuer URL & JWKS URI
		// instead of metadata discovery if we enable -skip-oidc-discovery.
		// In this case we need to make sure the required endpoints for
		// the provider are configured.
		if o.SkipOIDCDiscovery {
			if o.LoginURL == "" {
				msgs = append(msgs, "missing setting: login-url")
			}
			if o.RedeemURL == "" {
				msgs = append(msgs, "missing setting: redeem-url")
			}
			if o.OIDCJwksURL == "" {
				msgs = append(msgs, "missing setting: oidc-jwks-url")
			}
			keySet := oidc.NewRemoteKeySet(ctx, o.OIDCJwksURL)
			o.SetOIDCVerifier(oidc.NewVerifier(o.OIDCIssuerURL, keySet, &oidc.Config{
				ClientID:        o.ClientID,
				SkipIssuerCheck: o.InsecureOIDCSkipIssuerVerification,
			}))
		} else {
			// Configure discoverable provider data.
			provider, err := oidc.NewProvider(ctx, o.OIDCIssuerURL)
			if err != nil {
				return err
			}
			o.SetOIDCVerifier(provider.Verifier(&oidc.Config{
				ClientID:        o.ClientID,
				SkipIssuerCheck: o.InsecureOIDCSkipIssuerVerification,
			}))

			o.LoginURL = provider.Endpoint().AuthURL
			o.RedeemURL = provider.Endpoint().TokenURL
		}
		if o.Scope == "" {
			o.Scope = "openid email profile"

			if len(o.AllowedGroups) > 0 {
				o.Scope += " groups"
			}
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

	msgs = append(msgs, validateUpstreams(o.UpstreamServers)...)
	msgs = parseProviderInfo(o, msgs)

	if len(o.GoogleGroups) > 0 || o.GoogleAdminEmail != "" || o.GoogleServiceAccountJSON != "" {
		if len(o.GoogleGroups) < 1 {
			msgs = append(msgs, "missing setting: google-group")
		}
		if o.GoogleAdminEmail == "" {
			msgs = append(msgs, "missing setting: google-admin-email")
		}
		if o.GoogleServiceAccountJSON == "" {
			msgs = append(msgs, "missing setting: google-service-account-json")
		}
	}

	msgs = parseSignatureKey(o, msgs)
	msgs = configureLogger(o.Logging, msgs)

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
		Scope:            o.Scope,
		ClientID:         o.ClientID,
		ClientSecret:     o.ClientSecret,
		ClientSecretFile: o.ClientSecretFile,
		Prompt:           o.Prompt,
		ApprovalPrompt:   o.ApprovalPrompt,
		AcrValues:        o.AcrValues,
	}
	p.LoginURL, msgs = parseURL(o.LoginURL, "login", msgs)
	p.RedeemURL, msgs = parseURL(o.RedeemURL, "redeem", msgs)
	p.ProfileURL, msgs = parseURL(o.ProfileURL, "profile", msgs)
	p.ValidateURL, msgs = parseURL(o.ValidateURL, "validate", msgs)
	p.ProtectedResource, msgs = parseURL(o.ProtectedResource, "resource", msgs)

	// Make the OIDC options available to all providers that support it
	p.AllowUnverifiedEmail = o.InsecureOIDCAllowUnverifiedEmail
	p.EmailClaim = o.OIDCEmailClaim
	p.GroupsClaim = o.OIDCGroupsClaim
	p.Verifier = o.GetOIDCVerifier()
	p.JWTBearerVerifiers = o.GetJWTBearerVerifiers()

	// TODO (@NickMeves) - Remove This
	// Backwards Compatibility for Deprecated UserIDClaim option
	if o.OIDCEmailClaim == providers.OIDCEmailClaim &&
		o.UserIDClaim != providers.OIDCEmailClaim {
		p.EmailClaim = o.UserIDClaim
	}

	p.SetAllowedGroups(o.AllowedGroups)

	provider := providers.New(o.ProviderType, p)
	if provider == nil {
		msgs = append(msgs, fmt.Sprintf("invalid setting: provider '%s' is not available", o.ProviderType))
		return msgs
	}
	o.SetProvider(provider)

	switch p := o.GetProvider().(type) {
	case *providers.AzureProvider:
		p.Configure(o.AzureTenant)
	case *providers.GitHubProvider:
		p.SetOrgTeam(o.GitHubOrg, o.GitHubTeam)
		p.SetRepo(o.GitHubRepo, o.GitHubToken)
		p.SetUsers(o.GitHubUsers)
	case *providers.KeycloakProvider:
		// Backwards compatibility with `--keycloak-group` option
		if len(o.KeycloakGroups) > 0 {
			p.SetAllowedGroups(o.KeycloakGroups)
		}
	case *providers.GoogleProvider:
		if o.GoogleServiceAccountJSON != "" {
			file, err := os.Open(o.GoogleServiceAccountJSON)
			if err != nil {
				msgs = append(msgs, "invalid Google credentials file: "+o.GoogleServiceAccountJSON)
			} else {
				groups := o.AllowedGroups
				// Backwards compatibility with `--google-group` option
				if len(o.GoogleGroups) > 0 {
					groups = o.GoogleGroups
					p.SetAllowedGroups(groups)
				}
				p.SetGroupRestriction(groups, o.GoogleAdminEmail, file)
			}
		}
	case *providers.BitbucketProvider:
		p.SetTeam(o.BitbucketTeam)
		p.SetRepository(o.BitbucketRepository)
	case *providers.OIDCProvider:
		if p.Verifier == nil {
			msgs = append(msgs, "oidc provider requires an oidc issuer URL")
		}
	case *providers.GitLabProvider:
		p.Groups = o.GitLabGroup
		err := p.AddProjects(o.GitlabProjects)
		if err != nil {
			msgs = append(msgs, "failed to setup gitlab project access level")
		}
		p.SetAllowedGroups(p.PrefixAllowedGroups())
		p.SetProjectScope()

		if p.Verifier == nil {
			// Initialize with default verifier for gitlab.com
			ctx := context.Background()

			provider, err := oidc.NewProvider(ctx, "https://gitlab.com")
			if err != nil {
				msgs = append(msgs, "failed to initialize oidc provider for gitlab.com")
			} else {
				p.Verifier = provider.Verifier(&oidc.Config{
					ClientID: o.ClientID,
				})

				p.LoginURL, msgs = parseURL(provider.Endpoint().AuthURL, "login", msgs)
				p.RedeemURL, msgs = parseURL(provider.Endpoint().TokenURL, "redeem", msgs)
			}
		}
	case *providers.LoginGovProvider:
		p.PubJWKURL, msgs = parseURL(o.PubJWKURL, "pubjwk", msgs)

		// JWT key can be supplied via env variable or file in the filesystem, but not both.
		switch {
		case o.JWTKey != "" && o.JWTKeyFile != "":
			msgs = append(msgs, "cannot set both jwt-key and jwt-key-file options")
		case o.JWTKey == "" && o.JWTKeyFile == "":
			msgs = append(msgs, "login.gov provider requires a private key for signing JWTs")
		case o.JWTKey != "":
			// The JWT Key is in the commandline argument
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(o.JWTKey))
			if err != nil {
				msgs = append(msgs, "could not parse RSA Private Key PEM")
			} else {
				p.JWTKey = signKey
			}
		case o.JWTKeyFile != "":
			// The JWT key is in the filesystem
			keyData, err := ioutil.ReadFile(o.JWTKeyFile)
			if err != nil {
				msgs = append(msgs, "could not read key file: "+o.JWTKeyFile)
			}
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
			if err != nil {
				msgs = append(msgs, "could not parse private key from PEM file:"+o.JWTKeyFile)
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

	components := strings.Split(o.SignatureKey, ":")
	if len(components) != 2 {
		return append(msgs, "invalid signature hash:key spec: "+
			o.SignatureKey)
	}

	algorithm, secretKey := components[0], components[1]
	var hash crypto.Hash
	var err error
	if hash, err = hmacauth.DigestNameToCryptoHash(algorithm); err != nil {
		return append(msgs, "unsupported signature hash algorithm: "+
			o.SignatureKey)
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
