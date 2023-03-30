package options

type TenantMatcherRuleSource string

const (
	TenantMatcherRuleSourceHost        TenantMatcherRuleSource = "host"
	TenantMatcherRuleSourcePath        TenantMatcherRuleSource = "path"
	TenantMatcherRuleSourceQueryParams TenantMatcherRuleSource = "query"
	TenantMatcherRuleSourceHeader      TenantMatcherRuleSource = "header"
)

type TenantMatcherRule struct {
	Source       TenantMatcherRuleSource // which part of the HTTP request contains the tenant id
	Expr         string                  // the regex expression to match and extract tenant id from the source
	CaptureGroup int                     // capture group or sub-match that is actually the tenant id
	QueryParam   string                  // query parameter in case source is 'query'
	Header       string                  // header key in case source is 'header'
}

type TenantMatcher struct {
	Rules []*TenantMatcherRule
}
