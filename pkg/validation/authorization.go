package validation

import (
	"fmt"
	"os"
	"regexp"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
)

func validateAuthorization(authorization options.Authorization, reverseProxy bool) []string {
	msgs := []string{}

	msgs = append(msgs, validateRequestRules(authorization.RequestRules, reverseProxy)...)

	return msgs
}

func validateRequestRules(rules []options.AuthorizationRule, reverseProxy bool) []string {
	msgs := []string{}

	ids := make(map[string]struct{})

	for _, rule := range rules {
		msgs = append(msgs, validateRequestRule(ids, rule, reverseProxy)...)
	}

	return msgs
}

func validateRequestRule(ids map[string]struct{}, rule options.AuthorizationRule, reverseProxy bool) []string {
	msgs := []string{}

	if rule.ID == "" {
		msgs = append(msgs, "request rule has empty ID: IDs are required for all request rules")
	}

	if _, ok := ids[rule.ID]; ok {
		msgs = append(msgs, fmt.Sprintf("multiple request rules found with ID %q: request rule IDs must be unique", rule.ID))
	}
	ids[rule.ID] = struct{}{}

	msgs = append(msgs, validateRequestRulePolicy(rule.ID, rule.Policy)...)
	msgs = append(msgs, validateRequestRulePath(rule.ID, rule.Path)...)
	msgs = append(msgs, validateRequestRuleIPs(rule.ID, rule.IPs, reverseProxy)...)

	return msgs
}

func validateRequestRulePolicy(ruleID string, policy options.AuthorizationPolicy) []string {
	msgs := []string{}

	switch policy {
	case options.AllowPolicy, options.DenyPolicy, options.DelegatePolicy:
		// Do nothing for valid options
	default:
		msgs = append(msgs, fmt.Sprintf("request rule %q has invalid policy (%s): policy must be one of %s, %s or %s", ruleID, policy, options.AllowPolicy, options.DenyPolicy, options.DelegatePolicy))
	}

	return msgs
}

// validateRequestRulePath validates paths for path/regex based conditions
func validateRequestRulePath(ruleID string, path string) []string {
	msgs := []string{}

	_, err := regexp.Compile(path)
	if err != nil {
		msgs = append(msgs, fmt.Sprintf("error compiling path regex (%s) for rule %q: %v", path, ruleID, err))
	}

	return msgs
}

// validateRequestRuleIPs validates IP/CIDRs for IP based conditions.
func validateRequestRuleIPs(ruleID string, ips []string, reverseProxy bool) []string {
	msgs := []string{}

	if len(ips) > 0 && reverseProxy {
		_, err := fmt.Fprintln(os.Stderr, "WARNING: mixing IP authorization with --reverse-proxy is a potential security vulnerability. An attacker can inject a trusted IP into an X-Real-IP or X-Forwarded-For header if they aren't properly protected outside of oauth2-proxy")
		if err != nil {
			panic(err)
		}
	}

	for i, ipStr := range ips {
		if nil == ip.ParseIPNet(ipStr) {
			msgs = append(msgs, fmt.Sprintf("rule %q IP [%d] (%s) could not be recognized", ruleID, i, ipStr))
		}
	}

	return msgs
}
