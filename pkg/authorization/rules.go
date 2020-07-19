package authorization

import (
	"net"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

type AuthorizationPolicy int

const (
	NonePolicy AuthorizationPolicy = iota
	AllowPolicy
	DenyPolicy
)

type RuleSet interface {
	Matches(req *http.Request) AuthorizationPolicy
}

type rule struct {
	conditions []condition
	policy     AuthorizationPolicy
}

func (r rule) matches(req *http.Request) AuthorizationPolicy {
	for _, condition := range r.conditions {
		if !condition.matches(req) {
			// One of the conditions didn't match so this rule does not apply
			return NonePolicy
		}
	}
	// If all conditions match, return the configured rule policy
	return r.policy
}

func newRule(authRule options.AuthorizationRule, getClientIPFunc func(*http.Request) net.IP) (rule, error) {
	// This function should add the conditions in order of complexity, least complex first
	conditions := []condition{}

	if len(authRule.Methods) > 0 {
		conditions = append(conditions, newMethodCondition(authRule.Methods))
	}

	if len(authRule.Path) > 0 {
		condition, err := newPathCondition(authRule.Path)
		if err != nil {
			return rule{}, err
		}
		conditions = append(conditions, condition)
	}

	if len(authRule.IPs) > 0 {
		condition, err := newIPCondition(authRule.IPs, getClientIPFunc)
		if err != nil {
			return rule{}, err
		}
		conditions = append(conditions, condition)
	}

	var policy AuthorizationPolicy
	switch authRule.Policy {
	case options.AllowPolicy:
		policy = AllowPolicy
	case options.DenyPolicy:
		policy = DenyPolicy
	default:
		// This shouldn't be the case and should be prevented by validation
		policy = NonePolicy
	}

	return rule{
		conditions: conditions,
		policy:     policy,
	}, nil
}

type ruleSet struct {
	rules []rule
}

func (r ruleSet) Matches(req *http.Request) AuthorizationPolicy {
	for _, rule := range r.rules {
		if policy := rule.matches(req); policy != NonePolicy {
			// The rule applies to this request, return its policy
			return policy
		}
	}
	// No rules matched
	return NonePolicy
}

func NewRuleSet(requestRules options.RequestRules, getClientIPFunc func(*http.Request) net.IP) (RuleSet, error) {
	rules := []rule{}
	for _, requestRule := range requestRules {
		r, err := newRule(requestRule, getClientIPFunc)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return ruleSet{
		rules: rules,
	}, nil
}
