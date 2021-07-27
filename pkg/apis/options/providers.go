package options

import "github.com/oauth2-proxy/oauth2-proxy/v7/providers"

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
	// ADFSConfig holds all configurations for ADFS provider.
	ADFSConfig ADFSOptions `json:"ADFSConfig,omitempty"`
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

	// ID should be a unique identifier for the provider.
	// This value is required for all providers.
	ID string `json:"id,omitempty"`
	// Type is the OAuth provider
	// must be set from the supported providers group,
	// otherwise 'Google' is set as default
	Type string `json:"provider,omitempty"`
	// Name is the providers display name
	// if set, it will be shown to the users in the login page.
	Name string `json:"name,omitempty"`
	// CAFiles is a list of paths to CA certificates that should be used when connecting to the provider.
	// If not specified, the default Go trust sources are used instead
	CAFiles []string `json:"caFiles,omitempty"`

	// LoginURL is the authentication endpoint
	LoginURL string `json:"loginURL,omitempty"`
	// RedeemURL is the token redemption endpoint
	RedeemURL string `json:"redeemURL,omitempty"`
	// ProfileURL is the profile access endpoint
	ProfileURL string `json:"profileURL,omitempty"`
	// ProtectedResource is the resource that is protected (Azure AD and ADFS only)
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
	// Group enables to restrict login to members of indicated group
	Groups []string `json:"groups,omitempty"`
}

type AzureOptions struct {
	// Tenant directs to a tenant-specific or common (tenant-independent) endpoint
	// Default value is 'common'
	Tenant string `json:"tenant,omitempty"`
}

type ADFSOptions struct {
	// Skip adding the scope parameter in login request
	// Default value is 'false'
	SkipScope bool `json:"skipScope,omitempty"`
}

type BitbucketOptions struct {
	// Team sets restrict logins to members of this team
	Team string `json:"team,omitempty"`
	// Repository sets restrict logins to user with access to this repository
	Repository string `json:"repository,omitempty"`
}

type GitHubOptions struct {
	// Org sets restrict logins to members of this organisation
	Org string `json:"org,omitempty"`
	// Team sets restrict logins to members of this team
	Team string `json:"team,omitempty"`
	// Repo sets restrict logins to collaborators of this repository
	Repo string `json:"repo,omitempty"`
	// Token is the token to use when verifying repository collaborators
	// it must have push access to the repository
	Token string `json:"token,omitempty"`
	// Users allows users with these usernames to login
	// even if they do not belong to the specified org and team or collaborators
	Users []string `json:"users,omitempty"`
}

type GitLabOptions struct {
	// Group sets restrict logins to members of this group
	Group []string `json:"group,omitempty"`
	// Projects restricts logins to members of any of these projects
	Projects []string `json:"projects,omitempty"`
}

type GoogleOptions struct {
	// Groups sets restrict logins to members of this google group
	Groups []string `json:"group,omitempty"`
	// AdminEmail is the google admin to impersonate for api calls
	AdminEmail string `json:"adminEmail,omitempty"`
	// ServiceAccountJSON is the path to the service account json credentials
	ServiceAccountJSON string `json:"serviceAccountJson,omitempty"`
}

type OIDCOptions struct {
	// IssuerURL is the OpenID Connect issuer URL
	// eg: https://accounts.google.com
	IssuerURL string `json:"issuerURL,omitempty"`
	// InsecureAllowUnverifiedEmail prevents failures if an email address in an id_token is not verified
	// default set to 'false'
	InsecureAllowUnverifiedEmail bool `json:"insecureAllowUnverifiedEmail,omitempty"`
	// InsecureSkipIssuerVerification skips verification of ID token issuers. When false, ID Token Issuers must match the OIDC discovery URL
	// default set to 'false'
	InsecureSkipIssuerVerification bool `json:"insecureSkipIssuerVerification,omitempty"`
	// InsecureSkipNonce skips verifying the ID Token's nonce claim that must match
	// the random nonce sent in the initial OAuth flow. Otherwise, the nonce is checked
	// after the initial OAuth redeem & subsequent token refreshes.
	// default set to 'true'
	// Warning: In a future release, this will change to 'false' by default for enhanced security.
	InsecureSkipNonce bool `json:"insecureSkipNonce,omitempty"`
	// SkipDiscovery allows to skip OIDC discovery and use manually supplied Endpoints
	// default set to 'false'
	SkipDiscovery bool `json:"skipDiscovery,omitempty"`
	// JwksURL is the OpenID Connect JWKS URL
	// eg: https://www.googleapis.com/oauth2/v3/certs
	JwksURL string `json:"jwksURL,omitempty"`
	// EmailClaim indicates which claim contains the user email,
	// default set to 'email'
	EmailClaim string `json:"emailClaim,omitempty"`
	// GroupsClaim indicates which claim contains the user groups
	// default set to 'groups'
	GroupsClaim string `json:"groupsClaim,omitempty"`
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
			Type:           "google",
			Prompt:         "", // Change to "login" when ApprovalPrompt officially deprecated
			ApprovalPrompt: "force",
			AzureConfig: AzureOptions{
				Tenant: "common",
			},
			OIDCConfig: OIDCOptions{
				InsecureAllowUnverifiedEmail: false,
				InsecureSkipNonce:            true,
				SkipDiscovery:                false,
				UserIDClaim:                  providers.OIDCEmailClaim, // Deprecated: Use OIDCEmailClaim
				EmailClaim:                   providers.OIDCEmailClaim,
				GroupsClaim:                  providers.OIDCGroupsClaim,
			},
		},
	}
	return providers
}
