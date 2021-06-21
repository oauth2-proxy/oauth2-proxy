package redirect

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

var (
	// Used to check final redirects are not susceptible to open redirects.
	// Matches //, /\ and both of these with whitespace in between (eg / / or / \).
	invalidRedirectRegex = regexp.MustCompile(`[/\\](?:[\s\v]*|\.{1,2})[/\\]`)
)

// Validator is an interface to allow validation of application
// redirect URLs.
// As these values are determined from the request, they must go
// through thorough checks to ensure the safety of the end user.
type Validator interface {
	IsValidRedirect(redirect string) bool
}

// NewValidator constructs a new redirect validator.
func NewValidator(allowedDomains []string) Validator {
	return &validator{
		allowedDomains: allowedDomains,
	}
}

// validator implements the Validator interface to allow validation
// of redirect URLs.
type validator struct {
	allowedDomains []string
}

// IsValidRedirect checks whether the redirect URL is safe and allowed.
func (v *validator) IsValidRedirect(redirect string) bool {
	switch {
	case redirect == "":
		// The user didn't specify a redirect.
		// In this case, we expect the proxt to fallback to `/`
		return false
	case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") && !invalidRedirectRegex.MatchString(redirect):
		return true
	case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
		redirectURL, err := url.Parse(redirect)
		if err != nil {
			logger.Printf("Rejecting invalid redirect %q: scheme unsupported or missing", redirect)
			return false
		}
		redirectHostname := redirectURL.Hostname()

		for _, allowedDomain := range v.allowedDomains {
			allowedHost, allowedPort := splitHostPort(allowedDomain)
			if allowedHost == "" {
				continue
			}

			if redirectHostname == strings.TrimPrefix(allowedHost, ".") ||
				(strings.HasPrefix(allowedHost, ".") &&
					strings.HasSuffix(redirectHostname, allowedHost)) {
				// the domain names match, now validate the ports
				// if the whitelisted domain's port is '*', allow all ports
				// if the whitelisted domain contains a specific port, only allow that port
				// if the whitelisted domain doesn't contain a port at all, only allow empty redirect ports ie http and https
				redirectPort := redirectURL.Port()
				if allowedPort == "*" ||
					allowedPort == redirectPort ||
					(allowedPort == "" && redirectPort == "") {
					return true
				}
			}
		}

		logger.Printf("Rejecting invalid redirect %q: domain / port not in whitelist", redirect)
		return false
	default:
		logger.Printf("Rejecting invalid redirect %q: not an absolute or relative URL", redirect)
		return false
	}
}

// splitHostPort separates host and port. If the port is not valid, it returns
// the entire input as host, and it doesn't check the validity of the host.
// Unlike net.SplitHostPort, but per RFC 3986, it requires ports to be numeric.
// *** taken from net/url, modified validOptionalPort() to accept ":*"
func splitHostPort(hostport string) (host, port string) {
	host = hostport

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, port = host[:colon], host[colon+1:]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
// *** taken from net/url, modified to accept ":*"
func validOptionalPort(port string) bool {
	if port == "" || port == ":*" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}
