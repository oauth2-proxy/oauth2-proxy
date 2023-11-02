package providers

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

type AuthenticationMethod int64

const (
	// (default) https://oauth.net/2/client-authentication/
	ClientSecret AuthenticationMethod = iota
	// https://oauth.net/2/mtls/
	MutualTLS
	// https://oauth.net/private-key-jwt/
	PrivateKeyJWT
)

type ClientSecretAuthenticationData struct {
	// the OAuth Client Secret, either as a string or a file path
	ClientSecret     string
	ClientSecretFile string
}

type MutalTLSAuthenticationData struct {
	// Path to the PEM encoded X.509 certificate to use when connecting to the provider
	TLSCertFile string
	// Path to the PEM encoded X.509 key to use when connecting to the provider
	TLSKeyFile string
}

type PrivateKeyJWTAuthenticationData struct {
	// only one of the following should be set
	// can be one of the following: ecdsa.PrivateKey, rsa.PrivateKey
	JWTKey crypto.PrivateKey

	SigningMethod jwt.SigningMethod
	KeyId         string
	Expire        time.Duration
}

type AuthenticationConfig struct {
	// The authentication method to use when connecting to the provider
	AuthenticationMethod AuthenticationMethod
	// The authentication details to use when connecting to the provider
	// only one of the following should be set, according to the authentication method
	ClientSecretData  ClientSecretAuthenticationData
	MutalTLSData      MutalTLSAuthenticationData
	PrivateKeyJWTData PrivateKeyJWTAuthenticationData
}

func NewAuthenticationConfig(opts options.AuthenticationOptions) (*AuthenticationConfig, error) {
	switch opts.Method {
	case options.ClientSecret:
		return NewClientSecretAuthenticationConfig(opts)
	case options.MutualTLS:
		return NewMutualTLSAuthenticationConfig(opts)
	case options.PrivateKeyJWT:
		return NewPrivateKeyJWTAuthenticationConfig(opts)
	default:
		return nil, fmt.Errorf("unsupported authentication method: %v", opts.Method)
	}
}

func NewClientSecretAuthenticationConfig(opts options.AuthenticationOptions) (*AuthenticationConfig, error) {
	return &AuthenticationConfig{
		AuthenticationMethod: ClientSecret,
		ClientSecretData: ClientSecretAuthenticationData{
			ClientSecret:     opts.ClientSecret,
			ClientSecretFile: opts.ClientSecretFile,
		},
	}, nil
}

func NewMutualTLSAuthenticationConfig(opts options.AuthenticationOptions) (*AuthenticationConfig, error) {
	return &AuthenticationConfig{
		AuthenticationMethod: MutualTLS,
		MutalTLSData: MutalTLSAuthenticationData{
			TLSCertFile: opts.TLSCertFile,
			TLSKeyFile:  opts.TLSKeyFile,
		},
	}, nil
}

func NewPrivateKeyJWTAuthenticationConfig(opts options.AuthenticationOptions) (*AuthenticationConfig, error) {

	signingMethod, err := getJWTPrivateKeySigninMethod(opts)
	if err != nil {
		return nil, err
	}

	JWTKey, err := getJWTPrivateKeyObject(opts)
	if err != nil {
		return nil, err
	}

	return &AuthenticationConfig{
		AuthenticationMethod: PrivateKeyJWT,
		PrivateKeyJWTData: PrivateKeyJWTAuthenticationData{
			JWTKey:        JWTKey,
			SigningMethod: signingMethod,
			KeyId:         opts.JWTKeyId,
			Expire:        opts.JWTExpire,
		},
	}, nil
}

func getJWTPrivateKeySigninMethod(opts options.AuthenticationOptions) (jwt.SigningMethod, error) {
	var signingMethod jwt.SigningMethod
	switch opts.JWTAlgorithm {
	case "ES256":
		signingMethod = jwt.SigningMethodES256
	case "ES384":
		signingMethod = jwt.SigningMethodES384
	case "ES512":
		signingMethod = jwt.SigningMethodES512
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
	case "RS384":
		signingMethod = jwt.SigningMethodRS384
	case "RS512":
		signingMethod = jwt.SigningMethodRS512
	}
	return signingMethod, nil
}

func getJWTPrivateKeyObject(opts options.AuthenticationOptions) (crypto.PrivateKey, error) {
	var keyBytes []byte
	if opts.JWTKey != "" {
		keyBytes = []byte(opts.JWTKey)
	} else {
		keyData, err := os.ReadFile(opts.JWTKeyFile)
		if err != nil {
			return nil, fmt.Errorf("could not read key file: %v", opts.JWTKeyFile)
		}
		keyBytes = keyData
	}

	var JWTKey crypto.PrivateKey
	switch opts.JWTAlgorithm {
	case "ES256", "ES384", "ES512":
		signKey, err := jwt.ParseECPrivateKeyFromPEM(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse ECDSA private key from PEM file: %v", opts.JWTKeyFile)
		}
		JWTKey = signKey
	case "RS256", "RS384", "RS512":
		signKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse RSA private key from PEM file: %v", opts.JWTKeyFile)
		}
		JWTKey = signKey
	}

	return JWTKey, nil
}

func (a *AuthenticationConfig) GetClientSecret() (clientSecret string, err error) {
	switch a.AuthenticationMethod {
	case ClientSecret:
		return a.ClientSecretData.GetClientSecret()
	default:
		return "", errors.New("ClientSecret is not configured")
	}
}

func (a *ClientSecretAuthenticationData) GetClientSecret() (clientSecret string, err error) {
	if a.ClientSecret != "" || a.ClientSecretFile == "" {
		return a.ClientSecret, nil
	}

	// Getting ClientSecret can fail in runtime so we need to report it without returning the file name to the user
	fileClientSecret, err := os.ReadFile(a.ClientSecretFile)
	if err != nil {
		logger.Errorf("error reading client secret file %s: %s", a.ClientSecretFile, err)
		return "", errors.New("could not read client secret file")
	}
	return string(fileClientSecret), nil
}
