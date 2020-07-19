package options

type AuthorizationPolicy string

const (
	AllowPolicy AuthorizationPolicy = "Allow"
	DenyPolicy  AuthorizationPolicy = "Deny"
)

type AuthorizationRule struct {
	Policy  AuthorizationPolicy
	Path    string
	Methods []string
	IPs     []string
}

type RequestRules []AuthorizationRule
