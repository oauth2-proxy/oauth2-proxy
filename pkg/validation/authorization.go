package validation

import (
	"fmt"
	"regexp"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/ip"
)

func validateAuthorizationRules(rules options.RequestRules) []string {
	msgs := []string{}

	for _, rule := range rules {
		msgs = append(msgs, validateRequestRule(rule)...)
	}

	return msgs
}

func validateRequestRule(rule options.RequestRule) []string {
	msgs := []string{}

	if rule.ID == "" {
		msgs = append(msgs, "rule has empty id: ids are required for all request rules")
	}

	if !(rule.Policy == authorization.AllowPolicy ||
		rule.Policy == authorization.DenyPolicy ||
		rule.Policy == authorization.AuthPolicy) {
		msgs = append(msgs, fmt.Sprintf("invalid policy type: %s", rule.Policy))
	}

	_, err := regexp.Compile(rule.Path)
	if err != nil {
		msgs = append(msgs,
			fmt.Sprintf("unable to compile request rule path regex /%s/: %v", rule.Path, err))
	}

	for _, ruleIP := range rule.IPs {
		if ipNet := ip.ParseIPNet(ruleIP); ipNet == nil {
			msgs = append(msgs, fmt.Sprintf("could not parse trusted IP network(s): %s", ruleIP))
		}
	}

	return msgs
}
