package options

import (
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"
)

type RuleType string

const (
	ExactMatch  RuleType = "exact"
	PrefixMatch RuleType = "prefix"
	RegexMatch  RuleType = "regex"
)

type Rule struct {
	Domain string   `mapstructure:"match_rule_domain"`
	Path   string   `mapstructure:"match_rule_path"`
	Rule   RuleType `mapstructure:"match_rule_type"`
}

type MatchRules struct {
	Mode        string `mapstructure:"match_type"`
	RuleList    []Rule `mapstructure:"match_list"`
	RedirectURL *url.URL
}

func matchRulesDefaults() MatchRules {
	return MatchRules{
		Mode:        "whitelist",
		RuleList:    []Rule{},
		RedirectURL: &url.URL{},
	}
}

// 将通配符模式转换为正则表达式模式
func convertWildcardToRegex(pattern string) string {
	pattern = regexp.QuoteMeta(pattern)
	pattern = "^" + strings.ReplaceAll(pattern, "\\*", ".*") + "$"
	return pattern
}

func matchPattern(pattern string, target string, rule RuleType) bool {
	switch rule {
	case ExactMatch:
		return pattern == target
	case PrefixMatch:
		return strings.HasPrefix(target, pattern)
	case RegexMatch:
		matched, _ := regexp.MatchString(pattern, target)
		return matched
	default:
		return false
	}
}

func matchDomain(domain string, pattern string) bool {
	// 将通配符模式转换为正则模式
	regexPattern := convertWildcardToRegex(pattern)
	matched, _ := regexp.MatchString(regexPattern, domain)
	return matched
}

func matchDomainAndPath(domain, path string, rule Rule) bool {
	return matchDomain(domain, rule.Domain) && matchPattern(rule.Path, path, rule.Rule)
}

func IsAllowedByMode(domain, path string, config MatchRules, proxyPrefix string) bool {
	if domain == config.RedirectURL.Host && strings.HasPrefix(path, proxyPrefix) {
		return false
	}
	switch config.Mode {
	case "whitelist":
		for _, rule := range config.RuleList {
			if matchDomainAndPath(domain, path, rule) {
				return true
			}
		}
		return false
	case "blacklist":
		for _, rule := range config.RuleList {
			if matchDomainAndPath(domain, path, rule) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
