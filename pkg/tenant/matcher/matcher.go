package tenantmatcher

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
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
	case options.TenantMatcherRuleSourceHost:
		sourceStr = req.Host
	case options.TenantMatcherRuleSourcePath:
		sourceStr = req.URL.Path
	case options.TenantMatcherRuleSourceQueryParams:
		sourceStr = req.URL.Query().Get(r.conf.QueryParam)
	case options.TenantMatcherRuleSourceHeader:
		sourceStr = req.Header.Get(r.conf.Header)
	}

	cgs := r.regexp.FindStringSubmatch(sourceStr)
	var regexMatch string
	if r.conf.CaptureGroup < len(cgs) {
		regexMatch = cgs[r.conf.CaptureGroup]
	} else {
		return ""
	}

	if r.conf.JWTClaim != "" {
		return exractTenantIDFromJWT(regexMatch, r.conf.JWTClaim)
	}

	return regexMatch
}

type Matcher struct {
	rules []*rule
}

func New(conf options.TenantMatcher) (*Matcher, error) {
	matcher := &Matcher{}
	for _, ruleConf := range conf.Rules {
		rule, err := newRule(ruleConf)
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
		Source:       options.TenantMatcherRuleSourceQueryParams,
		QueryParam:   tenantutils.DefaultTenantIDQueryParam,
		Expr:         ".*",
		CaptureGroup: 0,
	})
	return rule
}

func exractTenantIDFromJWT(jwt string, claim string) string {
	subStrs := strings.Split(jwt, ".")
	if len(subStrs) != 3 {
		logger.Errorf("jwt token is not valid")
		return ""
	}
	jsonStr, err := base64.RawStdEncoding.DecodeString(subStrs[1])
	if err != nil {
		logger.Errorf("jwt payload is not a valid base64 encoded string: %v", err)
		return ""
	}
	value := gjson.Get(string(jsonStr), claim)
	return value.String()
}
