package options

import (
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
)

// RequestRules is a collection of request based authorization rules
type RequestRules []RequestRule

// RequestRule contains the various options to configure a request only
// based Rule that occurs before authentication
type RequestRule struct {
	// ID is a unique ID for the rule
	ID string

	// policy is either Allow, Deny or Auth
	Policy authorization.Policy

	// Path is a regex that will be tested against the req.URL.Path
	Path string

	// Methods is list of HTTP methods. This group is an OR operation.
	Methods []string

	// IPS is a list of IPs or CIDRs. This group is an OR operation
	IPs []string
}
