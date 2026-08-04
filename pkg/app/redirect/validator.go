package redirect

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"

	util "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
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
	case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//"):
		// Check path portion for open redirect patterns
		path := redirect
		queryString := ""
		if idx := strings.IndexAny(redirect, "?#"); idx != -1 {
			path = redirect[:idx]
			if redirect[idx] == '?' {
				queryString = redirect[idx+1:]
				if fragIdx := strings.Index(queryString, "#"); fragIdx != -1 {
					queryString = queryString[:fragIdx]
				}
			}
		}

		// Check path for open redirect patterns
		if invalidRedirectRegex.MatchString(path) {
			return false
		}

		// Check common redirect parameter values for open redirect patterns
		// These parameters are commonly used for redirects and should be validated
		redirectParams := []string{"url", "next", "redirect", "redir", "rurl", "redirect_uri", "desiredLocationUrl"}
		if queryString != "" {
			parsedQuery, err := url.ParseQuery(queryString)
			if err == nil {
				for _, param := range redirectParams {
					if values := parsedQuery[param]; len(values) > 0 {
						for _, value := range values {
							if invalidRedirectRegex.MatchString(value) {
								return false
							}
						}
					}
				}
			}
		}

		return true
	case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
		redirectURL, err := url.Parse(redirect)
		if err != nil {
			logger.Printf("Rejecting invalid redirect %q: scheme unsupported or missing", redirect)
			return false
		}

		if util.IsEndpointAllowed(redirectURL, v.allowedDomains) {
			return true
		}

		logger.Printf("Rejecting invalid redirect %q: domain / port not in whitelist", redirect)
		return false
	default:
		logger.Printf("Rejecting invalid redirect %q: not an absolute or relative URL", redirect)
		return false
	}
}
