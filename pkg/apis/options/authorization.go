package options

// AuthorizationPolicy is an enumeration of different authorization rule
// policies. Each policy determines a different action for a matching rule.
type AuthorizationPolicy string

const (
	// AllowPolicy when used, with a matching authorization rule, allows the
	// request without further authorization.
	AllowPolicy AuthorizationPolicy = "Allow"

	// DelegatePolicy when used, with a matching authorization rule, delegates
	// the authorization to the session based authorization.
	// This can only be used with request based authorization rules.
	DelegatePolicy AuthorizationPolicy = "Delegate"

	// DenyPolicy when used, with a matching authorization rule, denies the
	// request without further authorization.
	DenyPolicy AuthorizationPolicy = "Deny"
)

// Authorization contains fields to allow configuration of request authorization.
type Authorization struct {
	// RequestRules determines a set of rules for which each request to the proxy
	// should be matched against.
	// If any rule matches the request, the policy for the rule is applied to the
	// request.
	RequestRules []AuthorizationRule `json:"requestRules,omitempty"`
}

// AuthorizationRule determines the configuration for a particular authorization
// rule.

type AuthorizationRule struct {
	// Policy is the authorization policy to apply should the rule match the given
	// request.
	// All conditions specified within the rule must match the request for the
	// policy to be applied.
	// Valid values are Allow, Deny and Delegate.
	Policy AuthorizationPolicy

	// Path is a regex string that expects to match the HTTP request path.
	Path string

	// Methods is a list of HTTP methods to match against the HTTP request method.
	// If any method in the list matches the request method, this rule is
	// considered to match.
	Methods []string

	// IPs is a list of IP or network addresses (in CIDR notation) with which to
	// match the request client IP address.
	IPs []string
}
