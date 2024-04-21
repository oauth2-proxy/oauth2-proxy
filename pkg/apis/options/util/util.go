package util

import (
	"errors"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

// GetSecretValue returns the value of the Secret from its source
func GetSecretValue(source *options.SecretSource) ([]byte, error) {
	switch {
	case len(source.Value) > 0 && source.FromEnv == "" && source.FromFile == "":
		return []byte(source.Value), nil
	case len(source.Value) == 0 && source.FromEnv != "" && source.FromFile == "":
		return []byte(os.Getenv(source.FromEnv)), nil
	case len(source.Value) == 0 && source.FromEnv == "" && source.FromFile != "":
		return os.ReadFile(source.FromFile)
	default:
		return nil, errors.New("secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile")
	}
}
