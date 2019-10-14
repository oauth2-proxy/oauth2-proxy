package providers

import (
	"net/url"
)

type ExportingClaims []string

// ProviderData contains information required to configure all implementations
// of OAuth2 providers
type ProviderData struct {
	ProviderName      string
	ClientID          string
	ClientSecret      string
	LoginURL          *url.URL
	RedeemURL         *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	ValidateURL       *url.URL
	Scope             string
	ApprovalPrompt    string
	ExportingClaims   ExportingClaims
}

// AddressClaims represents the ODIC formatted address claim
// https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
type AddressClaims struct {
	Country       string `json:"country"`
	Formatted     string `json:"formatted"`
	Locality      string `json:"locality"`
	PostalCode    string `json:"postal_code"`
	Region        string `json:"region"`
	StreetAddress string `json:"street_address"`
}

// StandardClaims represents the OIDC core claims
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
type StandardClaims struct {
	Subject string `json:"sub" header:"sub"`

	Address             *AddressClaims `json:"address" header:",omitempty"`
	Birthdate           *string        `json:"birthdate" header:",omitempty"`
	Email               *string        `json:"email" header:",omitempty"`
	EmailVerified       *bool          `json:"email_verified" header:"email_verified,omitempty"`
	FamilyName          *string        `json:"family_name" header:",omitempty"`
	Gender              *string        `json:"gender" header:",omitempty"`
	GivenName           *string        `json:"given_name" header:",omitempty"`
	Locale              *string        `json:"locale" header:",omitempty"`
	MiddleName          *string        `json:"middle_name" header:"middle_name,omitempty"`
	Name                *string        `json:"name" header:",omitempty"`
	Nickname            *string        `json:"nickname" header:",omitempty"`
	PhoneNumber         *string        `json:"phone_number" header:"phone_number,omitempty"`
	PhoneNumberVerified *bool          `json:"phone_number_verified" header:"phone_number_verified,omitempty"`
	Picture             *string        `json:"picture" header:",omitempty"`
	PreferredUsername   *string        `json:"preferred_username" header:"preferred_username,omitempty"`
	Profile             *string        `json:"profile" header:",omitempty"`
	UpdatedAt           *int           `json:"updated_at" header:"updated_at,omitempty"`
	Website             *string        `json:"website" header:",omitempty"`
	Zoneinfo            *string        `json:"zoneinfo" header:",omitempty"`
}

// Data returns the ProviderData
func (p *ProviderData) Data() *ProviderData { return p }
