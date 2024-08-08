package redirect

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/Jing-ze/oauth2-proxy/pkg/util"
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
		_, err := url.Parse(redirect)
		if err != nil {
			util.Logger.Errorf("Rejecting invalid redirect %q: scheme unsupported or missing", redirect)
			return false
		}
		return true
	default:
		util.Logger.Infof("Rejecting invalid redirect %q: not an absolute or relative URL", redirect)
		return false
	}
}
