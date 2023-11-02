package validation

import (
	"os"

	"github.com/golang-jwt/jwt"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func validateAuthenticationConfig(authConfig options.AuthenticationOptions) []string {
	msgs := []string{}

	switch authConfig.Method {
	case options.ClientSecret:
		msgs = append(msgs, validateClientSecretAuthenticationConfig(authConfig)...)
	case options.MutualTLS:
		msgs = append(msgs, validateMutualTLSAuthenticationConfig(authConfig)...)
	case options.PrivateKeyJWT:
		msgs = append(msgs, validatePrivateKeyJWTAuthenticationConfig(authConfig)...)
	default:
		msgs = append(msgs, "invalid setting: authentication-method")
	}

	return msgs
}

func validateClientSecretAuthenticationConfig(authConfig options.AuthenticationOptions) []string {
	msgs := []string{}

	if authConfig.ClientSecret == "" && authConfig.ClientSecretFile == "" {
		msgs = append(msgs, "missing setting: client-secret or client-secret-file")
	}
	if authConfig.ClientSecret == "" && authConfig.ClientSecretFile != "" {
		_, err := os.ReadFile(authConfig.ClientSecretFile)
		if err != nil {
			msgs = append(msgs, "could not read client secret file: "+authConfig.ClientSecretFile)
		}
	}

	return msgs
}

func validateMutualTLSAuthenticationConfig(authConfig options.AuthenticationOptions) []string {
	msgs := []string{}

	if authConfig.TLSCertFile == "" {
		msgs = append(msgs, "missing setting: tls-cert-file")
	} else {
		_, err := os.ReadFile(authConfig.TLSCertFile)
		if err != nil {
			msgs = append(msgs, "could not read tls cert file: "+authConfig.TLSCertFile)
		}
	}
	if authConfig.TLSKeyFile == "" {
		msgs = append(msgs, "missing setting: tls-key-file")
	} else {
		_, err := os.ReadFile(authConfig.TLSKeyFile)
		if err != nil {
			msgs = append(msgs, "could not read tls cert file: "+authConfig.TLSCertFile)
		}
	}

	return msgs
}

func validatePrivateKeyJWTAuthenticationConfig(authConfig options.AuthenticationOptions) []string {
	msgs := []string{}

	if authConfig.JWTKey != "" && authConfig.JWTKeyFile != "" {
		msgs = append(msgs, "cannot set both jwt-key and jwt-key-file")
	}
	if authConfig.JWTKey == "" && authConfig.JWTKeyFile == "" {
		msgs = append(msgs, "missing setting: jwt-key or jwt-key-file")
	}
	if authConfig.JWTKey == "" && authConfig.JWTKeyFile != "" {
		_, err := os.ReadFile(authConfig.JWTKeyFile)
		if err != nil {
			msgs = append(msgs, "could not read jwt key file: "+authConfig.JWTKeyFile)
		}
	}

	// validate the key type is compatible with the provided key
	keyContent := authConfig.JWTKey
	if authConfig.JWTKeyFile != "" {
		fileContent, err := os.ReadFile(authConfig.JWTKeyFile)
		if err == nil {
			keyContent = string(fileContent)
		}
	}

	switch authConfig.JWTAlgorithm {
	case "ES256", "ES384", "ES512":
		_, err := jwt.ParseECPrivateKeyFromPEM([]byte(keyContent))
		if err != nil {
			msgs = append(msgs, "provided key failed to parse as an EC key: "+err.Error())
		}
	case "RS256", "RS384", "RS512":
		_, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(keyContent))
		if err != nil {
			msgs = append(msgs, "provided key failed to parse as an RSA key: "+err.Error())
		}
	}

	return msgs
}
