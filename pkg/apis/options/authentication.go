package options

import "time"

type AuthenticationMethod string

const (
	// ClientSecret is the authentication method for client secret
	// (default) https://oauth.net/2/client-authentication/
	ClientSecret AuthenticationMethod = "client_secret"

	// MutualTLS is the authentication method for mutual TLS
	// https://oauth.net/2/mtls/
	MutualTLS AuthenticationMethod = "mtls"

	// PrivateKeyJWT is the authentication method for private key JWT
	// https://oauth.net/private-key-jwt/
	PrivateKeyJWT AuthenticationMethod = "private_key_jwt"
)

type AuthenticationOptions struct {
	// Method defines how we should authenticate with the provider
	// possible values are: 'client_secret', 'mtls', 'private_key_jwt'
	Method AuthenticationMethod `json:"method,omitempty"`

	// ClientSecret is the OAuth Client Secret that is defined in the provider
	// This value is required when AuthenticationMethod is set to 'client_secret'
	ClientSecret string `json:"clientSecret,omitempty"`
	// ClientSecretFile is the name of the file
	// containing the OAuth Client Secret, it will be used if ClientSecret is not set.
	ClientSecretFile string `json:"clientSecretFile,omitempty"`

	// JWTKey is the private key used to sign the assertion
	// this is required when UseAssertionAuthentication is set to 'true'
	// only ecdsa keys are supported for now
	// it is required when AuthenticationMethod is set to 'private_key_jwt'
	// JWTKey is a private key in PEM format used to sign JWT,
	JWTKey string `json:"jwtKey,omitempty"`
	// JWTKeyFile is a path to the private key file in PEM format used to sign the JWT
	// it is required when AuthenticationMethod is set to 'private_key_jwt'
	JWTKeyFile string `json:"jwtKeyFile,omitempty"`
	// JWTAlgorithm is the algorithm used to sign the assertion
	// this defaults to 'ES256'
	// it is required when AuthenticationMethod is set to 'private_key_jwt'
	JWTAlgorithm string `json:"jwtAlgorithm,omitempty"`
	// JWTKeyId is the key id used to sign the assertion
	// it is used as the "kid" jwt token header in the assertion
	// if not provided, the "kid" header is not set
	// it is required when AuthenticationMethod is set to 'private_key_jwt'
	JWTKeyId string `json:"jwtKeyId,omitempty"`
	// JWTExpire is the duration for which the assertion is valid
	// this defaults to '5m'
	// it is required when AuthenticationMethod is set to 'private_key_jwt'
	JWTExpire time.Duration `json:"jwtExpire,omitempty"`

	// TLSCertFile Path to the PEM encoded X.509 certificate to use when connecting to the provider
	// it is required when AuthenticationMethod is set to 'mtls'
	TLSCertFile string `json:"tlsCertFile,omitempty"`
	// TLSKeyFile Path to the PEM encoded X.509 key to use when connecting to the provider
	// it is required when AuthenticationMethod is set to 'mtls'
	TLSKeyFile string `json:"tlsKeyFile,omitempty"`
}
