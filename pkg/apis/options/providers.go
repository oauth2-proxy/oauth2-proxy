package options

const (
	// OIDCEmailClaim is the generic email claim used by the OIDC provider.
	OIDCEmailClaim = "email"

	// OIDCGroupsClaim is the generic groups claim used by the OIDC provider.
	OIDCGroupsClaim = "groups"
)

// OIDCAudienceClaims is the generic audience claim list used by the OIDC provider.
var OIDCAudienceClaims = []string{"aud"}

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
	// MicrosoftEntraIDConfig holds all configurations for Entra ID provider.
	MicrosoftEntraIDConfig MicrosoftEntraIDOptions `json:"microsoftEntraIDConfig,omitempty"`
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
	Type ProviderType `json:"provider,omitempty"`
	// Name is the providers display name
	// if set, it will be shown to the users in the login page.
	Name string `json:"name,omitempty"`
	// CAFiles is a list of paths to CA certificates that should be used when connecting to the provider.
	// If not specified, the default Go trust sources are used instead
	CAFiles []string `json:"caFiles,omitempty"`
	// UseSystemTrustStore determines if your custom CA files and the system trust store are used
	// If set to true, your custom CA files and the system trust store are used otherwise only your custom CA files.
	UseSystemTrustStore bool `json:"useSystemTrustStore,omitempty"`
	// LoginURL is the authentication endpoint
	LoginURL string `json:"loginURL,omitempty"`
	// LoginURLParameters defines the parameters that can be passed from the start URL to the IdP login URL
	LoginURLParameters []LoginURLParameter `json:"loginURLParameters,omitempty"`
	// RedeemURL is the token redemption endpoint
	RedeemURL string `json:"redeemURL,omitempty"`
	// ProfileURL is the profile access endpoint
	ProfileURL string `json:"profileURL,omitempty"`
	// SkipClaimsFromProfileURL allows to skip request to Profile URL for resolving claims not present in id_token
	// default set to 'false'
	SkipClaimsFromProfileURL bool `json:"skipClaimsFromProfileURL,omitempty"`
	// ProtectedResource is the resource that is protected (Azure AD and ADFS only)
	ProtectedResource string `json:"resource,omitempty"`
	// ValidateURL is the access token validation endpoint
	ValidateURL string `json:"validateURL,omitempty"`
	// Scope is the OAuth scope specification
	Scope string `json:"scope,omitempty"`
	// AllowedGroups is a list of restrict logins to members of this group
	AllowedGroups []string `json:"allowedGroups,omitempty"`
	// The code challenge method
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	// URL to call to perform backend logout, `{id_token}` would be replaced by the actual `id_token` if available in the session
	BackendLogoutURL string `json:"backendLogoutURL"`
}

// ProviderType is used to enumerate the different provider type options
// Valid options are: adfs, azure, bitbucket, digitalocean facebook, github,
// gitlab, google, keycloak, keycloak-oidc, linkedin, login.gov, nextcloud
// and oidc.
type ProviderType string

const (
	// ADFSProvider is the provider type for ADFS
	ADFSProvider ProviderType = "adfs"

	// AzureProvider is the provider type for Azure
	AzureProvider ProviderType = "azure"

	// MicrosoftEntraIDProvider is the provider type for Entra OIDC
	MicrosoftEntraIDProvider ProviderType = "entra-id"

	// BitbucketProvider is the provider type for Bitbucket
	BitbucketProvider ProviderType = "bitbucket"

	// DigitalOceanProvider is the provider type for DigitalOcean
	DigitalOceanProvider ProviderType = "digitalocean"

	// FacebookProvider is the provider type for Facebook
	FacebookProvider ProviderType = "facebook"

	// GitHubProvider is the provider type for GitHub
	GitHubProvider ProviderType = "github"

	// GitLabProvider is the provider type for GitLab
	GitLabProvider ProviderType = "gitlab"

	// GoogleProvider is the provider type for GoogleProvider
	GoogleProvider ProviderType = "google"

	// KeycloakProvider is the provider type for Keycloak
	KeycloakProvider ProviderType = "keycloak"

	// KeycloakOIDCProvider is the provider type for Keycloak OIDC
	KeycloakOIDCProvider ProviderType = "keycloak-oidc"

	// LinkedInProvider is the provider type for LinkedIn
	LinkedInProvider ProviderType = "linkedin"

	// LoginGovProvider is the provider type for LoginGov
	LoginGovProvider ProviderType = "login.gov"

	// NextCloudProvider is the provider type for NextCloud
	NextCloudProvider ProviderType = "nextcloud"

	// OIDCProvider is the provider type for OIDC
	OIDCProvider ProviderType = "oidc"
)

type KeycloakOptions struct {
	// Group enables to restrict login to members of indicated group
	Groups []string `json:"groups,omitempty"`

	// Role enables to restrict login to users with role (only available when using the keycloak-oidc provider)
	Roles []string `json:"roles,omitempty"`
}

type AzureOptions struct {
	// Tenant directs to a tenant-specific or common (tenant-independent) endpoint
	// Default value is 'common'
	Tenant string `json:"tenant,omitempty"`
	// GraphGroupField configures the group field to be used when building the groups list from Microsoft Graph
	// Default value is 'id'
	GraphGroupField string `json:"graphGroupField,omitempty"`
}

type MicrosoftEntraIDOptions struct {
	// AllowedTenants is a list of allowed tenants. In case of multi-tenant apps, incoming tokens are
	// issued by different issuers and OIDC issuer verification needs to be disabled.
	// When not specified, all tenants are allowed. Redundant for single-tenant apps
	// (regular ID token validation matches the issuer).
	AllowedTenants []string `json:"allowedTenants,omitempty"`
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
	// Projects restricts logins to members of these projects
	Projects []string `json:"projects,omitempty"`
}

type GoogleOptions struct {
	// Groups sets restrict logins to members of this Google group
	Groups []string `json:"group,omitempty"`
	// AdminEmail is the Google admin to impersonate for api calls
	AdminEmail string `json:"adminEmail,omitempty"`
	// ServiceAccountJSON is the path to the service account json credentials
	ServiceAccountJSON string `json:"serviceAccountJson,omitempty"`
	// UseApplicationDefaultCredentials is a boolean whether to use Application Default Credentials instead of a ServiceAccountJSON
	UseApplicationDefaultCredentials bool `json:"useApplicationDefaultCredentials,omitempty"`
	// TargetPrincipal is the Google Service Account used for Application Default Credentials
	TargetPrincipal string `json:"targetPrincipal,omitempty"`
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
	// AudienceClaim allows to define any claim that is verified against the client id
	// By default `aud` claim is used for verification.
	AudienceClaims []string `json:"audienceClaims,omitempty"`
	// ExtraAudiences is a list of additional audiences that are allowed
	// to pass verification in addition to the client id.
	ExtraAudiences []string `json:"extraAudiences,omitempty"`
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
			Type: "google",
			AzureConfig: AzureOptions{
				Tenant: "common",
			},
			OIDCConfig: OIDCOptions{
				InsecureAllowUnverifiedEmail: false,
				InsecureSkipNonce:            true,
				SkipDiscovery:                false,
				UserIDClaim:                  OIDCEmailClaim, // Deprecated: Use OIDCEmailClaim
				EmailClaim:                   OIDCEmailClaim,
				GroupsClaim:                  OIDCGroupsClaim,
				AudienceClaims:               OIDCAudienceClaims,
				ExtraAudiences:               []string{},
			},
		},
	}
	return providers
}
