package options

// Providers is a collection of definitions for providers.
type Providers []Provider

// Provider holds all provider configuration
type Provider struct {
	ClientID         string `json:"clientID,omitempty"`
	ClientSecret     string `json:"clientSecret,omitempty"`
	ClientSecretFile string `json:"clientSecretFile,omitempty"`

	KeycloakConfig  KeycloakOptions  `json:"keycloakConfig,omitempty"`
	AzureConfig     AzureOptions     `json:"azureConfig,omitempty"`
	BitbucketConfig BitbucketOptions `json:"bitbucketConfig,omitempty"`
	GitHubConfig    GitHubOptions    `json:"githubConfig,omitempty"`
	GitLabConfig    GitLabOptions    `json:"gitlabConfig,omitempty"`
	GoogleConfig    GoogleOptions    `json:"googleConfig,omitempty"`
	OIDCConfig      OIDCOptions      `json:"oidcConfig,omitempty"`
	LoginGovConfig  LoginGovOptions  `json:"loginGovConfig,omitempty"`

	ProviderID      string   `json:"providerID,omitempty"`
	ProviderType    string   `json:"provider,omitempty"`
	ProviderName    string   `json:"providerDisplayName,omitempty"`
	ProviderCAFiles []string `json:"providerCAFiles,omitempty"`

	LoginURL          string   `json:"loginURL,omitempty"`
	RedeemURL         string   `json:"redeemURL,omitempty"`
	ProfileURL        string   `json:"profileURL,omitempty"`
	ProtectedResource string   `json:"resource,omitempty"`
	ValidateURL       string   `json:"validateURL,omitempty"`
	Scope             string   `json:"scope,omitempty"`
	Prompt            string   `json:"prompt,omitempty"`
	ApprovalPrompt    string   `json:"approvalPrompt,omitempty"`
	AllowedGroups     []string `json:"allowedGroups,omitempty"`

	AcrValues string `json:"acrValues,omitempty"`
}

type KeycloakOptions struct {
	KeycloakGroups []string `json:"keycloakGroups,omitempty"`
}

type AzureOptions struct {
	AzureTenant string `json:"azureTenant,omitempty"`
}

type BitbucketOptions struct {
	BitbucketTeam       string `json:"bitbucketTeam,omitempty"`
	BitbucketRepository string `json:"bitbucketRepository,omitempty"`
}

type GitHubOptions struct {
	GitHubOrg   string   `json:"githubOrg,omitempty"`
	GitHubTeam  string   `json:"githubTeam,omitempty"`
	GitHubRepo  string   `json:"githubRepo,omitempty"`
	GitHubToken string   `json:"githubToken,omitempty"`
	GitHubUsers []string `json:"githubUsers,omitempty"`
}

type GitLabOptions struct {
	GitLabGroup    []string `json:"gitlabGroups,omitempty"`
	GitLabProjects []string `json:"gitLabProjects,omitempty"`
}

type GoogleOptions struct {
	GoogleGroups             []string `json:"googleGroup,omitempty"`
	GoogleAdminEmail         string   `json:"googleAdminEmail,omitempty"`
	GoogleServiceAccountJSON string   `json:"googleServiceAccountJson,omitempty"`
}

type OIDCOptions struct {
	OIDCIssuerURL                      string `json:"oidcIssuerURL,omitempty"`
	InsecureOIDCAllowUnverifiedEmail   bool   `json:"insecureOidcAllowUnverifiedEmail,omitempty"`
	InsecureOIDCSkipIssuerVerification bool   `json:"insecureOidcSkipIssuerVerification,omitempty"`
	SkipOIDCDiscovery                  bool   `json:"skipOidcDiscovery,omitempty"`
	OIDCJwksURL                        string `json:"oidcJwksURL,omitempty"`
	OIDCGroupsClaim                    string `json:"oidcGroupsClaim,omitempty,omitempty"`
	OIDCEmailClaim                     string `json:"oidcEmailClaim,omitempty,omitempty"`
	UserIDClaim                        string `json:"userIDClaim,omitempty,omitempty"`
}

type LoginGovOptions struct {
	JWTKey     string `json:"jwtKey,omitempty"`
	JWTKeyFile string `json:"jwtKeyFile,omitempty"`
	PubJWKURL  string `json:"pubjwkURL,omitempty"`
}

func providerDefaults() Providers {
	providers := Providers{
		Provider{
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
