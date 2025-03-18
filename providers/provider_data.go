package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/higress-group/oauth2-proxy/pkg/apis/options"
	"github.com/higress-group/oauth2-proxy/pkg/apis/sessions"
	"github.com/higress-group/oauth2-proxy/pkg/middleware"
	oidc "github.com/higress-group/oauth2-proxy/pkg/providers/go_oidc"
	internaloidc "github.com/higress-group/oauth2-proxy/pkg/providers/oidc"
	"github.com/higress-group/oauth2-proxy/pkg/providers/util"
	pkgutil "github.com/higress-group/oauth2-proxy/pkg/util"
)

const (
	// This is not exported as it's not currently user configurable
	oidcUserClaim = "sub"
)

// ProviderData contains information required to configure all implementations
// of OAuth2 providers
type ProviderData struct {
	ProviderName string
	LoginURL     *url.URL
	RedeemURL    *url.URL
	ProfileURL   *url.URL
	ValidateURL  *url.URL
	ClientID     string
	ClientSecret string
	Scope        string
	// The picked CodeChallenge Method or empty if none.
	CodeChallengeMethod string
	// Code challenge methods supported by the Provider
	SupportedCodeChallengeMethods []string `json:"code_challenge_methods_supported,omitempty"`

	// Common OIDC options for any OIDC-based providers to consume
	UserClaim                string
	EmailClaim               string
	GroupsClaim              string
	Verifier                 internaloidc.IDTokenVerifier
	NeedsVerifier            bool
	SkipClaimsFromProfileURL bool

	// Universal Group authorization data structure
	// any provider can set to consume
	AllowedGroups map[string]struct{}

	getAuthorizationHeaderFunc func(string) http.Header
	loginURLParameterDefaults  url.Values
	loginURLParameterOverrides map[string]*regexp.Regexp

	RedeemTimeout   uint32
	VerifierTimeout uint32
	StoredSession   *middleware.StoredSessionLoader
}

// Data returns the ProviderData
func (p *ProviderData) Data() *ProviderData { return p }

func (p *ProviderData) GetClientSecret() (clientSecret string, err error) {
	if p.ClientSecret != "" {
		return p.ClientSecret, nil
	}
	return "", errors.New("provider client secret is empty")
}

// LoginURLParams returns the parameter values that should be passed to the IdP
// login URL.  This is the default set of parameters configured for this provider,
// optionally overridden by the given overrides (typically from the URL of the
// /oauth2/start request) according to the configured rules for this provider.
func (p *ProviderData) LoginURLParams(overrides url.Values) url.Values {
	// the returned url.Values may be modified later in the request handling process
	// so shallow clone the default map
	params := url.Values{}
	for k, v := range p.loginURLParameterDefaults {
		params[k] = v
	}
	if len(overrides) > 0 {
		for param, re := range p.loginURLParameterOverrides {
			if reqValues, ok := overrides[param]; ok {
				actualValues := make([]string, 0, len(reqValues))
				for _, val := range reqValues {
					if re.MatchString(val) {
						actualValues = append(actualValues, val)
					}
				}
				if len(actualValues) > 0 {
					params.Del(param)
					params[param] = actualValues
				}
			}
		}
	}
	return params
}

// Compile the given set of LoginURLParameter options into the internal defaults
// and regular expressions used to validate any overrides.
func (p *ProviderData) compileLoginParams(paramConfig []options.LoginURLParameter) []error {
	var errs []error
	p.loginURLParameterDefaults = url.Values{}
	p.loginURLParameterOverrides = make(map[string]*regexp.Regexp)

	for _, param := range paramConfig {
		if p.seenParameter(param.Name) {
			errs = append(errs, fmt.Errorf("parameter %s provided more than once in loginURLParameters", param.Name))
		} else {
			// record default if parameter declares one
			if len(param.Default) > 0 {
				p.loginURLParameterDefaults[param.Name] = param.Default
			}
			// record allow rules if any
			if len(param.Allow) > 0 {
				errs = p.convertAllowRules(errs, param)
			}
		}
	}
	return errs
}

// Converts the list of allow rules for the given parameter into a regexp
// and store it for use at runtime when validating overrides of that parameter.
func (p *ProviderData) convertAllowRules(errs []error, param options.LoginURLParameter) []error {
	var allowREs []string
	for idx, rule := range param.Allow {
		if (rule.Value == nil) == (rule.Pattern == nil) {
			errs = append(errs, fmt.Errorf("rule %d in LoginURLParameter %s must have exactly one of value or pattern", idx, param.Name))
		} else {
			allowREs = append(allowREs, regexpForRule(rule))
		}
	}
	if re, err := regexp.Compile(strings.Join(allowREs, "|")); err != nil {
		errs = append(errs, err)
	} else {
		p.loginURLParameterOverrides[param.Name] = re
	}
	return errs
}

// Check whether we have already processed a configuration for the given parameter name
func (p *ProviderData) seenParameter(name string) bool {
	_, seenDefault := p.loginURLParameterDefaults[name]
	_, seenOverride := p.loginURLParameterOverrides[name]
	return seenDefault || seenOverride
}

// Generate a validating regular expression pattern for a given URLParameterRule.
// If the rule is for a fixed value then returns a regexp that matches exactly
// that value, if the rule is itself a regexp just use that as-is.
func regexpForRule(rule options.URLParameterRule) string {
	if rule.Value != nil {
		// convert literal value into an equivalent regexp,
		// anchored at start and end
		return "^" + regexp.QuoteMeta(*rule.Value) + "$"
	}
	// just use the pattern as-is, but wrap in a non-capture group
	// to avoid any possibility of confusing the outer disjunction.
	return "(?:" + *rule.Pattern + ")"
}

// setAllowedGroups organizes a group list into the AllowedGroups map
// to be consumed by Authorize implementations
func (p *ProviderData) setAllowedGroups(groups []string) {
	p.AllowedGroups = make(map[string]struct{}, len(groups))
	for _, group := range groups {
		p.AllowedGroups[group] = struct{}{}
	}
}

type providerDefaults struct {
	name        string
	loginURL    *url.URL
	redeemURL   *url.URL
	profileURL  *url.URL
	validateURL *url.URL
	scope       string
}

func (p *ProviderData) setProviderDefaults(defaults providerDefaults) {
	p.ProviderName = defaults.name
	p.LoginURL = defaultURL(p.LoginURL, defaults.loginURL)
	p.RedeemURL = defaultURL(p.RedeemURL, defaults.redeemURL)
	p.ProfileURL = defaultURL(p.ProfileURL, defaults.profileURL)
	p.ValidateURL = defaultURL(p.ValidateURL, defaults.validateURL)

	if p.Scope == "" {
		p.Scope = defaults.scope
	}

	if p.UserClaim == "" {
		p.UserClaim = oidcUserClaim
	}
}

// defaultURL will set return a default value if the given value is not set.
func defaultURL(u *url.URL, d *url.URL) *url.URL {
	if u != nil && u.String() != "" {
		// The value is already set
		return u
	}

	// If the default is given, return that
	if d != nil {
		return d
	}
	return &url.URL{}
}

// ****************************************************************************
// These private OIDC helper methods are available to any providers that are
// OIDC compliant
// ****************************************************************************

func (p *ProviderData) verifyIDToken(ctx context.Context, token *pkgutil.Token) (*oidc.IDToken, error) {
	rawIDToken := getIDToken(token)
	if strings.TrimSpace(rawIDToken) == "" {
		return nil, ErrMissingIDToken
	}
	if p.Verifier == nil {
		return nil, ErrMissingOIDCVerifier
	}
	return p.Verifier.Verify(ctx, rawIDToken)
}

// buildSessionFromClaims uses IDToken claims to populate a fresh SessionState
// with non-Token related fields.
func (p *ProviderData) buildSessionFromClaims(rawIDToken, accessToken string) (*sessions.SessionState, error) {
	ss := &sessions.SessionState{}

	if rawIDToken == "" {
		return ss, nil
	}

	extractor, err := p.getClaimExtractor(rawIDToken, accessToken)
	if err != nil {
		return nil, err
	}

	// Use a slice of a struct (vs map) here in case the same claim is used twice
	nickName := ""
	for _, c := range []struct {
		claim string
		dst   interface{}
	}{
		{p.UserClaim, &ss.User},
		{p.EmailClaim, &ss.Email},
		{p.GroupsClaim, &ss.Groups},
		{"preferred_username", &ss.PreferredUsername},
		{"nickname", &nickName},
	} {
		if _, err := extractor.GetClaimInto(c.claim, c.dst); err != nil {
			return nil, err
		}
	}
	if ss.PreferredUsername == "" && nickName != "" {
		ss.PreferredUsername = nickName
	}
	return ss, nil
}

func (p *ProviderData) getClaimExtractor(rawIDToken, accessToken string) (util.ClaimExtractor, error) {
	profileURL := p.ProfileURL
	if p.SkipClaimsFromProfileURL {
		profileURL = &url.URL{}
	}

	extractor, err := util.NewClaimExtractor(rawIDToken, profileURL, p.getAuthorizationHeader(accessToken))
	if err != nil {
		return nil, fmt.Errorf("could not initialise claim extractor: %v", err)
	}

	return extractor, nil
}

// checkNonce compares the session's nonce with the IDToken's nonce claim
func (p *ProviderData) checkNonce(s *sessions.SessionState) error {
	extractor, err := p.getClaimExtractor(s.IDToken, "")
	if err != nil {
		return fmt.Errorf("id_token claims extraction failed: %v", err)
	}
	var nonce string
	if _, err := extractor.GetClaimInto("nonce", &nonce); err != nil {
		return fmt.Errorf("could not extract nonce from ID Token: %v", err)
	}

	if !s.CheckNonce(nonce) {
		return errors.New("id_token nonce claim does not match the session nonce")
	}
	return nil
}

func (p *ProviderData) getAuthorizationHeader(accessToken string) http.Header {
	if p.getAuthorizationHeaderFunc != nil && accessToken != "" {
		return p.getAuthorizationHeaderFunc(accessToken)
	}
	return nil
}
