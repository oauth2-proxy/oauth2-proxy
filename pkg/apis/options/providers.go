package options

// Providers is a collection of definitions for providers.
type Providers []Provider

// Provider holds all configuration for a single provider
type Provider struct {
	// ClientID is the OAuth Client ID that is defined in the provider
	// This value is required for all providers.
	ClientID string `json:"clientID,omitempty"`
	// ClientSecret is the OAuth Client Secret that is defined in the provider
	// This value is required for all providers.
	ClientSecret string `json:"clientSecret,omitempty"`
	// ClientSecretFile is the name of the file
	// containing the OAuth Client Secret, it will be used if ClientSecret is not set.
	ClientSecretFile string `json:"clientSecretFile,omitempty"`

	// KeycloakConfig holds all configurations for Keycloak provider.
	KeycloakConfig KeycloakOptions `json:"keycloakConfig,omitempty"`
	// AzureConfig holds all configurations for Azure provider.
	AzureConfig AzureOptions `json:"azureConfig,omitempty"`
	// BitbucketConfig holds all configurations for Bitbucket provider.
	BitbucketConfig BitbucketOptions `json:"bitbucketConfig,omitempty"`
	// GitHubConfig holds all configurations for GitHubC provider.
	GitHubConfig GitHubOptions `json:"githubConfig,omitempty"`
	// GitLabConfig holds all configurations for GitLab provider.
	GitLabConfig GitLabOptions `json:"gitlabConfig,omitempty"`
	// GoogleConfig holds all configurations for Google provider.
	GoogleConfig GoogleOptions `json:"googleConfig,omitempty"`
	// OIDCConfig holds all configurations for OIDC provider
	// or providers utilize OIDC configurations.
	OIDCConfig OIDCOptions `json:"oidcConfig,omitempty"`
	// LoginGovConfig holds all configurations for LoginGov provider.
	LoginGovConfig LoginGovOptions `json:"loginGovConfig,omitempty"`

	// ProviderID should be a unique identifier for the provider.
	// This value is required for all providers.
	ProviderID string `json:"providerID,omitempty"`
	// ProviderType is the OAuth provider
	// must be set from the supported providers group,
	// otherwise 'Google' is set as default
	ProviderType string `json:"provider,omitempty"`
	// ProviderName is the providers display name
	// if set, it will be shown to the users in the login page.
	ProviderName string `json:"providerDisplayName,omitempty"`
	// ProviderCAFiles is a list of paths to CA certificates that should be used when connecting to the provider.
	// If not specified, the default Go trust sources are used instead
	ProviderCAFiles []string `json:"providerCAFiles,omitempty"`

	// LoginURL is the authentication endpoint
	LoginURL string `json:"loginURL,omitempty"`
	// RedeemURL is the token redemption endpoint
	RedeemURL string `json:"redeemURL,omitempty"`
	// ProfileURL is the profile access endpoint
	ProfileURL string `json:"profileURL,omitempty"`
	// ProtectedResource is the resource that is protected (Azure AD only)
	ProtectedResource string `json:"resource,omitempty"`
	// ValidateURL is the access token validation endpoint
	ValidateURL string `json:"validateURL,omitempty"`
	// Scope is the OAuth scope specification
	Scope string `json:"scope,omitempty"`
	// Prompt is OIDC prompt
	Prompt string `json:"prompt,omitempty"`
	// ApprovalPrompt is the OAuth approval_prompt
	// default is set to 'force'
	ApprovalPrompt string `json:"approvalPrompt,omitempty"`
	// AllowedGroups is a list of restrict logins to members of this group
	AllowedGroups []string `json:"allowedGroups,omitempty"`

	// AcrValues is a string of acr values
	AcrValues string `json:"acrValues,omitempty"`
}

type KeycloakOptions struct {
	// KeycloakGroups enables to restrict login to members of indicated group
	KeycloakGroups []string `json:"keycloakGroups,omitempty"`
}

type AzureOptions struct {
	// AzureTenant directs to a tenant-specific or common (tenant-independent) endpoint
	// Default value is 'commmon'
	AzureTenant string `json:"azureTenant,omitempty"`
}

type BitbucketOptions struct {
	// BitbucketTeam sets restrict logins to members of this team
	BitbucketTeam string `json:"bitbucketTeam,omitempty"`
	// BitbucketRepository sets restrict logins to user with access to this repository
	BitbucketRepository string `json:"bitbucketRepository,omitempty"`
}

type GitHubOptions struct {
	// GitHubOrg sets restrict logins to members of this organisation
	GitHubOrg string `json:"githubOrg,omitempty"`
	// GitHubTeam sets restrict logins to members of this team
	GitHubTeam string `json:"githubTeam,omitempty"`
	// GitHubRepo sets restrict logins to collaborators of this repository
	GitHubRepo string `json:"githubRepo,omitempty"`
	// GitHubToken is the token to use when verifying repository collaborators
	// it must have push access to the repository
	GitHubToken string `json:"githubToken,omitempty"`
	// GitHubUsers allows users with these usernames to login
	// even if they do not belong to the specified org and team or collaborators
	GitHubUsers []string `json:"githubUsers,omitempty"`
}

type GitLabOptions struct {
	// GitLabGroup sets restrict logins to members of this group
	GitLabGroup []string `json:"gitLabGroups,omitempty"`
	// GitLabProjects sets restrict logins to members of any of these projects
	GitLabProjects []string `json:"gitLabProjects,omitempty"`
}

type GoogleOptions struct {
	// GoogleGroups sets restrict logins to members of this google group
	GoogleGroups []string `json:"googleGroup,omitempty"`
	// GoogleAdminEmail is the google admin to impersonate for api calls
	GoogleAdminEmail string `json:"googleAdminEmail,omitempty"`
	// GoogleServiceAccountJSON is the path to the service account json credentials
	GoogleServiceAccountJSON string `json:"googleServiceAccountJson,omitempty"`
}

type OIDCOptions struct {
	// OIDCIssuerURL is the OpenID Connect issuer URL
	// ie: https://accounts.google.com
	OIDCIssuerURL string `json:"oidcIssuerURL,omitempty"`
	// InsecureOIDCAllowUnverifiedEmail preventes failur if an email address in an id_token is not verified
	// default set to 'false'
	InsecureOIDCAllowUnverifiedEmail bool `json:"insecureOidcAllowUnverifiedEmail,omitempty"`
	// InsecureOIDCSkipIssuerVerification skips verification if issuer matches OIDC discovery URL
	// default set to 'false'
	InsecureOIDCSkipIssuerVerification bool `json:"insecureOidcSkipIssuerVerification,omitempty"`
	// SkipOIDCDiscovery allows to skip OIDC discovery and use manually supplied Endpoints
	// default set to 'false'
	SkipOIDCDiscovery bool `json:"skipOidcDiscovery,omitempty"`
	// OIDCJwksURL is the OpenID Connect JWKS URL
	// ie: https://www.googleapis.com/oauth2/v3/certs
	OIDCJwksURL string `json:"oidcJwksURL,omitempty"`
	// OIDCGroupsClaim indicates which claim contains the user groups
	// default set to 'groups'
	OIDCGroupsClaim string `json:"oidcGroupsClaim,omitempty"`
	// OIDCEmailClaim indicates which claim contains the user email
	// defualt set to 'email'
	OIDCEmailClaim string `json:"oidcEmailClaim,omitempty,omitempty"`
	// UserIDClaim indicates which claim contains the user ID
	// default set to 'email'
	UserIDClaim string `json:"userIDClaim,omitempty"`
}

type LoginGovOptions struct {
	// JWTKey is a private key in PEM format used to sign JWT,
	JWTKey string `json:"jwtKey,omitempty"`
	// JWTKeyFile is a path to the private key file in PEM format used to sign the JWT
	JWTKeyFile string `json:"jwtKeyFile,omitempty"`
	// PubJWKURL is the JWK pubkey access endpoint
	PubJWKURL string `json:"pubjwkURL,omitempty"`
}

func providerDefaults() Providers {
	providers := Providers{
		{
			ProviderType:   "google",
			Prompt:         "", // Change to "login" when ApprovalPrompt officially deprecated
			ApprovalPrompt: "force",
			AzureConfig: AzureOptions{
				AzureTenant: "common",
			},
			OIDCConfig: OIDCOptions{
				UserIDClaim:                      "email",
				InsecureOIDCAllowUnverifiedEmail: false,
				SkipOIDCDiscovery:                false,
				OIDCGroupsClaim:                  "groups",
			},
		},
	}
	return providers
}
