package providers

import (
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
	JWTKey interface{}

	Algorithm     string
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
	switch opts.AuthenticationMethod {
	case options.ClientSecret:
		return &AuthenticationConfig{
			AuthenticationMethod: ClientSecret,
			ClientSecretData: ClientSecretAuthenticationData{
				ClientSecret:     opts.ClientSecret,
				ClientSecretFile: opts.ClientSecretFile,
			},
		}, nil
	case options.MutualTLS:
		return &AuthenticationConfig{
			AuthenticationMethod: MutualTLS,
			MutalTLSData: MutalTLSAuthenticationData{
				TLSCertFile: opts.TLSCertFile,
				TLSKeyFile:  opts.TLSKeyFile,
			},
		}, nil
	case options.PrivateKeyJWT:
		var signingMethod jwt.SigningMethod
		var signingAlgorithmType string
		switch opts.JWTAlgorithm {
		case "ES256":
			signingMethod = jwt.SigningMethodES256
			signingAlgorithmType = "ECDSA"
		case "ES384":
			signingMethod = jwt.SigningMethodES384
			signingAlgorithmType = "ECDSA"
		case "ES512":
			signingMethod = jwt.SigningMethodES512
			signingAlgorithmType = "ECDSA"
		case "RS256":
			signingMethod = jwt.SigningMethodRS256
			signingAlgorithmType = "RSA"
		case "RS384":
			signingMethod = jwt.SigningMethodRS384
			signingAlgorithmType = "RSA"
		case "RS512":
			signingMethod = jwt.SigningMethodRS512
			signingAlgorithmType = "RSA"
		}

		// JWT key can be supplied via env variable or file in the filesystem, but not both.
		var JWTKey interface{}
		switch {
		case opts.JWTKey != "" && opts.JWTKeyFile != "":
			return nil, errors.New("cannot set both jwt-key and jwt-key-file options")
		case opts.JWTKey == "" && opts.JWTKeyFile == "":
			return nil, errors.New("provider requires a private key for signing JWTs")
		case opts.JWTKey != "" && signingAlgorithmType == "RSA":
			// The JWT Key is in the commandline argument
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(opts.JWTKey))
			if err != nil {
				return nil, fmt.Errorf("could not parse ECDSA Private Key PEM: %v", err)
			}
			JWTKey = signKey
		case opts.JWTKeyFile != "" && signingAlgorithmType == "RSA":
			// The JWT key is in the filesystem
			keyData, err := os.ReadFile(opts.JWTKeyFile)
			if err != nil {
				return nil, fmt.Errorf("could not read key file: %v", opts.JWTKeyFile)
			}
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
			if err != nil {
				return nil, fmt.Errorf("could not parse ECDSA private key from PEM file: %v", opts.JWTKeyFile)
			}
			JWTKey = signKey
		case opts.JWTKey != "" && signingAlgorithmType == "ECDSA":
			// The JWT Key is in the commandline argument
			signKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(opts.JWTKey))
			if err != nil {
				return nil, fmt.Errorf("could not parse ECDSA Private Key PEM: %v", err)
			}
			JWTKey = signKey
		case opts.JWTKeyFile != "" && signingAlgorithmType == "ECDSA":
			// The JWT key is in the filesystem
			keyData, err := os.ReadFile(opts.JWTKeyFile)
			if err != nil {
				return nil, fmt.Errorf("could not read key file: %v", opts.JWTKeyFile)
			}
			signKey, err := jwt.ParseECPrivateKeyFromPEM(keyData)
			if err != nil {
				return nil, fmt.Errorf("could not parse ECDSA private key from PEM file: %v", opts.JWTKeyFile)
			}
			JWTKey = signKey
		}

		return &AuthenticationConfig{
			AuthenticationMethod: PrivateKeyJWT,
			PrivateKeyJWTData: PrivateKeyJWTAuthenticationData{
				JWTKey:        JWTKey,
				Algorithm:     opts.JWTAlgorithm,
				SigningMethod: signingMethod,
				KeyId:         opts.JWTKeyId,
				Expire:        opts.JWTExpire,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported authentication method: %v", opts.AuthenticationMethod)
	}
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
