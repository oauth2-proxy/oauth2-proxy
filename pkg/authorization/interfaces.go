package authorization

import (
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

// Policy is a Rule policy name
type Policy string

const (
	AllowPolicy = Policy("ALLOW")
	DenyPolicy  = Policy("DENY")
	AuthPolicy  = Policy("AUTH")
	SkipPolicy  = Policy("SKIP")
)

// Rule represents an authorization rule to be used for Allow & Deny
// policies based on Request or SessionState fields
type Rule interface {
	// Match returns the Policy if the rule matches
	Match(*http.Request, *sessions.SessionState) Policy
}

// RulesEngine manages Allow & Deny logic on a hierarchical Rules list
type RulesEngine interface {
	// AddRule adds a Rule to the hierarchical Rules list. First in
	// takes precedence.
	AddRule(Rule)

	// Match returns the Policy name of the first matching Rule in the
	// hierarchical Rules list.
	Match(*http.Request, *sessions.SessionState) Policy
}
