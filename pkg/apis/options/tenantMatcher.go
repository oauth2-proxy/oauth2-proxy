package options

type TenantMatcherRuleSource string

const (
	TenantMatcherRuleSourceHost        TenantMatcherRuleSource = "host"
	TenantMatcherRuleSourcePath        TenantMatcherRuleSource = "path"
	TenantMatcherRuleSourceQueryParams TenantMatcherRuleSource = "query"
	TenantMatcherRuleSourceHeader      TenantMatcherRuleSource = "header"
)

type TenantMatcherRule struct {

	// Source defines which part of the HTTP request contains the tenant id
	Source TenantMatcherRuleSource

	// Expr defines the regex expression to match and extract tenant id from the source
	Expr string

	// CaptureGroup or sub-match referes to the index that is actually the tenant id
	CaptureGroup int

	// QueryParam defines the query parameter containing tenant-id in case source is 'query'
	QueryParam string

	// Header defines the header key in case source is 'header'
	Header string
}

type TenantMatcher struct {
	Rules []*TenantMatcherRule
}
