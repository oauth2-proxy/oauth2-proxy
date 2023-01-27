package tenantmatcher

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	tenantutils "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/tenant/utils"
)

type rule struct {
	conf   *options.TenantMatcherRule
	regexp *regexp.Regexp
}

func newRule(conf options.TenantMatcherRule) (*rule, error) {
	if conf.CaptureGroup < 0 {
		return nil, fmt.Errorf("capture group cannot be -ve")
	}
	r := &rule{
		conf: &conf,
	}
	regexp, err := regexp.Compile(conf.Expr)
	if err != nil {
		return nil, fmt.Errorf("unable to compile regexp '%s': %w", conf.Expr, err)
	}
	r.regexp = regexp
	return r, nil
}

func (r *rule) execute(req *http.Request) string {
	sourceStr := ""
	// get the source string based on rule.source
	switch r.conf.Source {
	case options.TenantMatcherRuleSource_Host:
		sourceStr = req.Host
	case options.TenantMatcherRuleSource_Path:
		sourceStr = req.URL.Path
	case options.TenantMatcherRuleSource_QueryParams:
		sourceStr = req.URL.Query().Get(r.conf.QueryParam)
	case options.TenantMatcherRuleSource_Header:
		sourceStr = req.Header.Get(r.conf.Header)
	}

	// get the capture groups
	cgs := r.regexp.FindStringSubmatch(sourceStr)
	if r.conf.CaptureGroup < len(cgs) {
		return cgs[r.conf.CaptureGroup]
	}
	return ""
}

type Matcher struct {
	rules []*rule
}

func New(conf options.TenantMatcher) (*Matcher, error) {
	matcher := &Matcher{}
	for _, ruleConf := range conf.Rules {
		rule, err := newRule(*ruleConf)
		if err != nil {
			return nil, fmt.Errorf("unable to create new rule: %w", err)
		}
		matcher.rules = append(matcher.rules, rule)
	}

	matcher.rules = append(matcher.rules, defaultRule())

	return matcher, nil
}

// returns tenantId, returns empty string if unable to match
func (matcher *Matcher) Match(req *http.Request) string {
	for _, rule := range matcher.rules {
		id := rule.execute(req)
		if id != "" {
			return id
		}
	}
	return ""
}

// default rule will be added to our list of rules in any case
// this helps with self-redirects to oauth2 proxy, and oauth2 proxy will inject the tenantId in http request
func defaultRule() *rule {
	rule, _ := newRule(options.TenantMatcherRule{
		Source:       options.TenantMatcherRuleSource_QueryParams,
		QueryParam:   tenantutils.DefaultTenantIdQueryParam,
		Expr:         ".*",
		CaptureGroup: 0,
	})
	return rule
}
