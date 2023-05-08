package options

// Source defines the source i-e "host", "path", "query" or "header"
type TenantMatcherRuleSource string

const (
	TenantMatcherRuleSourceHost        TenantMatcherRuleSource = "host"
	TenantMatcherRuleSourcePath        TenantMatcherRuleSource = "path"
	TenantMatcherRuleSourceQueryParams TenantMatcherRuleSource = "query"
	TenantMatcherRuleSourceHeader      TenantMatcherRuleSource = "header"
)

// TenantMatcherRule is the structure to define rule for finding tenant id in request
type TenantMatcherRule struct {

	// Source defines which part of the HTTP request contains the tenant id
	Source TenantMatcherRuleSource `json:"source,omitempty"`

	// Expr defines the regex expression to match and extract tenant id from the source
	Expr string `json:"expr,omitempty"`

	// CaptureGroup or sub-match referes to the index that is actually the tenant id
	CaptureGroup int `json:"captureGroup,omitempty"`

	// QueryParam defines the query parameter containing tenant-id in case source is 'query'
	QueryParam string `json:"queryParam,omitempty"`

	// Header defines the header key in case source is 'header'
	Header string `json:"header,omitempty"`

	// JWT Claim defines the json field containing tenant id in jwt token e.g tenant.id
	JWTClaim string `json:"jwtClaim,omitempty"`
}

type TenantMatcher struct {
	// Rules define the rules for finding tenant id in the incoming request
	Rules []TenantMatcherRule `json:"rules,omitempty"`
}
