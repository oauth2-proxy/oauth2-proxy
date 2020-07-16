package authorization

import (
	"fmt"
	"net/http"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization/conditions"
)

// RequestRuleOptions are the various options to configure a request only
// based Rule that occurs before authentication
type RequestRuleOptions struct {
	// ID is a unique ID for the rule
	ID string

	// policy is either Allow or Deny
	Policy Policy

	// Path is a regex that will be tested against the req.URL.Path
	Path string

	// methods is list of HTTP methods. This group is an OR operation.
	Methods []string

	// IPS is a list of IPs or CIDRs. This group is an OR operation
	IPs []string
}

// rule represents an authorization rule to be used for Allow & Deny
// policies on fields in a request & a session
type rule struct {
	id         string
	policy     Policy
	conditions []conditions.Condition
}

// NewRequestRule creates a new request based authorization rule
func NewRequestRule(opts RequestRuleOptions, ipParser ipapi.RealClientIPParser) (Rule, error) {
	if !(opts.Policy == AllowPolicy || opts.Policy == DenyPolicy || opts.Policy == AuthPolicy) {
		return nil, fmt.Errorf("invalid policy type: %s", opts.Policy)
	}

	var conds []conditions.Condition

	if opts.Path != "" {
		pathCond, err := conditions.NewPath(opts.Path)
		if err != nil {
			return nil, err
		}
		conds = append(conds, pathCond)
	}

	if opts.Methods != nil {
		conds = append(conds, conditions.NewMethods(opts.Methods))
	}

	if opts.IPs != nil {
		nsCond, err := conditions.NewIPs(opts.IPs, ipParser)
		if err != nil {
			return nil, err
		}
		conds = append(conds, nsCond)
	}

	return &rule{
		id:         opts.ID,
		policy:     opts.Policy,
		conditions: conds,
	}, nil
}

// Match checks if a rules could match the conditions. If yes, it returns
// the policy of the rule. If no, it returns SkipPolicy
func (r *rule) Match(req *http.Request, ss *sessions.SessionState) Policy {
	for _, c := range r.conditions {
		if !c.Match(req, ss) {
			return SkipPolicy
		}
	}
	return r.policy
}
