package util

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
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

// GetRequestHost return the request host header or X-Forwarded-Host if present
func GetRequestHost(req *http.Request) string {
	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}
	return host
}
