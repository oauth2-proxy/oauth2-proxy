package validation

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/authentication/hmacauth"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
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
	msgs = append(msgs, validateAPIRoutes(o)...)
	msgs = configureLogger(o.Logging, msgs)
	msgs = parseSignatureKey(o, msgs)

	if o.SSLInsecureSkipVerify {
		transport := requests.DefaultTransport.(*http.Transport)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- InsecureSkipVerify is a configurable option we allow
	} else if len(o.Providers[0].CAFiles) > 0 {
		pool, err := util.GetCertPool(o.Providers[0].CAFiles, ptr.Deref(o.Providers[0].UseSystemTrustStore, options.DefaultUseSystemTrustStore))
		if err == nil {
			transport := requests.DefaultTransport.(*http.Transport)
			transport.TLSClientConfig = &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			}
		} else {
			msgs = append(msgs, fmt.Sprintf("unable to load provider CA file(s): %v", err))
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

			var jwtIssuersHeaders map[string]string
			if len(o.ExtraJwtIssuersHeaders) > 0 {
				jwtIssuersHeaders, msgs = parseJwtIssuerHeader(o.ExtraJwtIssuersHeaders, msgs)
			} else {
				jwtIssuersHeaders = make(map[string]string) // Initialize an empty map if headers are not provided
			}

			for _, jwtIssuer := range jwtIssuers {
				verifier, err := newVerifierFromJwtIssuer(
					o.Providers[0].OIDCConfig.AudienceClaims,
					o.Providers[0].OIDCConfig.ExtraAudiences,
					jwtIssuer,
					jwtIssuersHeaders,
				)
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

// parseJwtIssuerHeader takes in an array of header strings in the form of "headerKey=headerValue"
// and parses them to return a map of key-value pairs and any error messages.
//
// Parameters:
//
//	headers: A slice of strings representing headerKey=headerValue entries.
//	msgs: A slice of strings to collect error messages, if any.
//
// Returns:
//
//	map[string]string: A map of key-value pairs extracted from the headers.
//	[]string: A slice of strings containing any error messages encountered during parsing.
//
// Description:
// This function parses the input headers and extracts key-value pairs from them.
// Each entry in the "headers" slice should be in the format "headerKey=headerValue".
// The function checks if each entry contains both a non-empty key and a non-empty value.
// If so, it adds the key-value pair to the resulting map. If any errors are encountered
// during parsing, they are appended to the "msgs" slice.
// The function returns the map of key-value pairs and the error messages.
func parseJwtIssuerHeader(headers []string, msgs []string) (map[string]string, []string) {
	result := make(map[string]string)

	if len(headers) == 0 {
		msgs = append(msgs, "empty header array")
		return result, msgs
	}

	for _, headerItem := range headers {
		components := strings.SplitN(strings.TrimSpace(headerItem), "=", 2)
		if len(components) != 2 {
			msgs = append(msgs, fmt.Sprintf("invalid jwt issuer header format, expected header_name=header_value: %s", headerItem))
			continue
		}

		key := strings.TrimSpace(components[0])
		value := strings.TrimSpace(components[1])
		if key != "" && value != "" {
			// Add the non-empty key and value to the result map
			result[key] = value
		}
	}

	return result, msgs
}

// newVerifierFromJwtIssuer takes in issuer information in jwtIssuer info and returns
// a verifier for that issuer.
func newVerifierFromJwtIssuer(audienceClaims []string, extraAudiences []string, jwtIssuer jwtIssuer, jwtIssuersHeaders map[string]string) (internaloidc.IDTokenVerifier, error) {
	pvOpts := internaloidc.ProviderVerifierOptions{
		AudienceClaims:      audienceClaims,
		ClientID:            jwtIssuer.audience,
		ExtraAudiences:      extraAudiences,
		IssuerURL:           jwtIssuer.issuerURI,
		IssuerCustomHeaders: jwtIssuersHeaders,
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
