package authorization

import (
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

// engine manages authorization Rules and which requests
// pass or fail authorization
type engine struct {
	rules         []Rule
	defaultPolicy Policy
}

// NewRulesEngine builds a RulesEngine for HTTP request based authZ
func NewRulesEngine(rules []Rule, defaultPolicy Policy) RulesEngine {
	return &engine{
		rules:         rules,
		defaultPolicy: defaultPolicy,
	}
}

// Match compares an http.Request & SessionState against our list of rules for
// a given policy. Per rule, if a SkipPolicy is encountered it keeps going.
// Otherwise it returns the policy of the matched rule
func (e *engine) Match(req *http.Request, ss *sessions.SessionState) Policy {
	for _, rule := range e.rules {
		match := rule.Match(req, ss)
		if match == SkipPolicy {
			continue
		} else {
			return match
		}
	}
	return e.defaultPolicy
}
