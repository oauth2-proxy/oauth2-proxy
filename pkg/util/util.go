package util

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

func GetCertPool(paths []string) (*x509.CertPool, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("invalid empty list of Root CAs file paths")
	}
	pool := x509.NewCertPool()
	for _, path := range paths {
		// Cert paths are a configurable option
		data, err := ioutil.ReadFile(path) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("certificate authority file (%s) could not be read - %s", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("loading certificate authority (%s) failed", path)
		}
	}
	return pool, nil
}

// GetFromNestedMap traverses through a potentially-nested map using the given slice of keys. If a value exists in that
// nested field then the value is returned, otherwise nil is returned and the second return value is false. This method
// is intended to mimic the interface for the standard [] operator on maps.
func GetFromNestedMap(m map[string]interface{}, ks ...string) (interface{}, bool) {
	if len(ks) == 0 {
		return nil, false
	}

	v, ok := m[ks[0]]

	if !ok || len(ks) == 1 {
		return v, ok
	}

	m, ok = v.(map[string]interface{})

	if !ok {
		return nil, false
	}

	return GetFromNestedMap(m, ks[1:]...)
}
