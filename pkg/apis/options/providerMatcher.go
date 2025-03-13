package options

// Source defines the source i-e "host", "path", "query" or "header"
type ProviderMatcherRuleSource string

const (
	ProviderMatcherRuleSourceHost        ProviderMatcherRuleSource = "host"
	ProviderMatcherRuleSourcePath        ProviderMatcherRuleSource = "path"
	ProviderMatcherRuleSourceQueryParams ProviderMatcherRuleSource = "query"
	ProviderMatcherRuleSourceHeader      ProviderMatcherRuleSource = "header"
)

// ProviderMatcherRule is the structure to define rule for finding provider id in request
type ProviderMatcherRule struct {

	// Source defines which part of the HTTP request contains the provider id
	Source ProviderMatcherRuleSource `json:"source,omitempty"`

	// Expr defines the regex expression to match and extract provider id from the source
	Expr string `json:"expr,omitempty"`

	// CaptureGroup or sub-match referes to the index that is actually the provider id
	CaptureGroup int `json:"captureGroup,omitempty"`

	// QueryParam defines the query parameter containing provider-id in case source is 'query'
	QueryParam string `json:"queryParam,omitempty"`

	// Header defines the header key in case source is 'header'
	Header string `json:"header,omitempty"`

	// JWT Claim defines the json field containing provider id in jwt token e.g provider.id
	JWTClaim string `json:"jwtClaim,omitempty"`
}

type ProviderMatcher struct {
	// Rules define the rules for finding provider id in the incoming request
	Rules []ProviderMatcherRule `json:"rules,omitempty"`
}
