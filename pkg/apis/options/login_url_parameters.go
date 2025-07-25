package options

// LoginURLParameter is the configuration for a single query parameter that
// can be passed through from the `/oauth2/start` endpoint to the IdP login
// URL.  The "default" option specifies the default value or values (if any)
// that will be passed to the IdP for this parameter, and "allow" is a list
// of options for ways in which this parameter can be set or overridden via
// the query string to `/oauth2/start`.
// If _only_ a default is specified and no "allow" then the parameter is
// effectively fixed - the default value will always be used and anything
// passed to the start URL will be ignored.  If _only_ "allow" is specified
// but no default then the parameter will only be passed on to the IdP if
// the caller provides it, and no value will be sent otherwise.
//
// Examples:
//
// # A parameter whose value is fixed
//
// ```
// name: organization
// default:
// - myorg
// ```
//
// A parameter that is not passed by default, but may be set to one of a
// fixed set of values
//
// ```
// name: prompt
// allow:
// - value: login
// - value: consent
// - value: select_account
// ```
//
// A parameter that is passed by default but may be overridden by one of
// a fixed set of values
//
// ```
// name: prompt
// default: ["login"]
// allow:
// - value: consent
// - value: select_account
// ```
//
// A parameter that may be overridden, but only by values that match a
// regular expression.  For example to restrict `login_hint` to email
// addresses in your organization's domain:
//
// ```
// name: login_hint
// allow:
// - pattern: '^[^@]*@example\.com$'
// # this allows at most one "@" sign, and requires "example.com" domain.
// ```
//
// Note that the YAML rules around exactly which characters are allowed
// and/or require escaping in different types of string literals are
// convoluted.  For regular expressions the single quoted form is simplest
// as backslash is not considered to be an escape character.  Alternatively
// use the "chomped block" format `|-`:
//
// ```
//   - pattern: |-
//     ^[^@]*@example\.com$
//
// ```
//
// The hyphen is important, a `|` block would have a trailing newline
// character.
type LoginURLParameter struct {
	// Name specifies the name of the query parameter.
	Name string `yaml:"name"`

	// Default specifies a default value or values that will be
	// passed to the IdP if not overridden.
	//+optional
	Default []string `yaml:"default,omitempty"`

	// Allow specifies rules about how the default (if any) may be
	// overridden via the query string to `/oauth2/start`.  Only
	// values that match one or more of the allow rules will be
	// forwarded to the IdP.
	//+optional
	Allow []URLParameterRule `yaml:"allow,omitempty"`
}

// URLParameterRule represents a rule by which query parameters
// passed to the `/oauth2/start` endpoint are checked to determine whether
// they are valid overrides for the given parameter passed to the IdP's
// login URL.  Either Value or Pattern should be supplied, not both.
type URLParameterRule struct {
	// A Value rule matches just this specific value
	Value *string `yaml:"value,omitempty"`

	// A Pattern rule gives a regular expression that must be matched by
	// some substring of the value.  The expression is _not_ automatically
	// anchored to the start and end of the value, if you _want_ to restrict
	// the whole parameter value you must anchor it yourself with `^` and `$`.
	Pattern *string `yaml:"pattern,omitempty"`
}
