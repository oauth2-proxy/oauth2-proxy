package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func GetCertPool(paths []string, useSystemPool bool) (*x509.CertPool, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("invalid empty list of Root CAs file paths")
	}

	var pool *x509.CertPool
	if useSystemPool {
		rootPool, err := getSystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("unable to get SystemCertPool when append is true - #{err}")
		}
		pool = rootPool
	} else {
		pool = x509.NewCertPool()
	}

	return loadCertsFromPaths(paths, pool)

}

func getSystemCertPool() (*x509.CertPool, error) {
	rootPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed getting system cert pool: %w", err)
	}

	if rootPool == nil {
		return nil, fmt.Errorf("SystemCertPool is empty")
	}

	return rootPool, nil
}

func loadCertsFromPaths(paths []string, pool *x509.CertPool) (*x509.CertPool, error) {
	for _, path := range paths {
		// Cert paths are a configurable option
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("certificate authority file (%s) could not be read - %s", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("loading certificate authority (%s) failed", path)
		}
	}
	return pool, nil
}

func getClientCertificates(certFile, keyFile string) ([]tls.Certificate, error) {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to locate certificate %s: %w", certFile, err)
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to locate key %s: %w", keyFile, err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("could not parse cert/key pair %s, %s: %w", certFile, keyFile, err)
	}

	return []tls.Certificate{cert}, nil
}

func GetHTTPClient(certFile, keyFile string, insecureSkipVerify bool, useSystemPool bool, caFiles ...string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if insecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	} else if len(caFiles) > 0 {
		pool, err := GetCertPool(caFiles, useSystemPool)
		if err != nil {
			return nil, fmt.Errorf("could not build TLS truststore for client: %w", err)
		}

		transport.TLSClientConfig.RootCAs = pool
	}

	if certFile != "" && keyFile != "" {
		certs, err := getClientCertificates(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("unable to parse TLS client certificates: %w", err)
		}
		transport.TLSClientConfig.Certificates = certs
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

// https://golang.org/src/crypto/tls/generate_cert.go as a function
func GenerateCert(ipaddr string) ([]byte, []byte, error) {
	var err error

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, keyBytes, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, keyBytes, err
	}

	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"OAuth2 Proxy Test Suite"},
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		IPAddresses: []net.IP{net.ParseIP(ipaddr)},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	return certBytes, keyBytes, err
}

// SplitHostPort separates host and port. If the port is not valid, it returns
// the entire input as host, and it doesn't check the validity of the host.
// Unlike net.SplitHostPort, but per RFC 3986, it requires ports to be numeric.
// *** taken from net/url, modified validOptionalPort() to accept ":*"
func SplitHostPort(hostport string) (host, port string) {
	host = hostport

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, port = host[:colon], host[colon+1:]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
// *** taken from net/url, modified to accept ":*"
func validOptionalPort(port string) bool {
	if port == "" || port == ":*" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// IsEndpointAllowed checks whether the endpoint URL is allowed based
// on an allowed domains list.
func IsEndpointAllowed(endpoint *url.URL, allowedDomains []string) bool {
	hostname := endpoint.Hostname()

	for _, allowedDomain := range allowedDomains {
		allowedHost, allowedPort := SplitHostPort(allowedDomain)
		if allowedHost == "" {
			continue
		}

		if isHostnameAllowed(hostname, allowedHost) {
			// the domain names match, now validate the ports
			// if the allowed domain's port is '*', allow all ports
			// if the allowed domain contains a specific port, only allow that port
			// if the allowed domain doesn't contain a port at all, only allow empty redirect ports ie http and https
			redirectPort := endpoint.Port()
			if allowedPort == "*" ||
				allowedPort == redirectPort ||
				(allowedPort == "" && redirectPort == "") {
				return true
			}
		}
	}

	return false
}

func isHostnameAllowed(hostname, allowedHost string) bool {
	// check if we have a perfect match between hostname and allowedHost
	if hostname == strings.TrimPrefix(allowedHost, ".") ||
		hostname == strings.TrimPrefix(allowedHost, "*.") {
		return true
	}

	// check if hostname is a sub domain of the allowedHost
	if (strings.HasPrefix(allowedHost, ".") && strings.HasSuffix(hostname, allowedHost)) ||
		(strings.HasPrefix(allowedHost, "*.") && strings.HasSuffix(hostname, allowedHost[1:])) {
		return true
	}

	return false
}

// RemoveDuplicateStr removes duplicates from a slice of strings.
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]struct{})
	var list []string
	for _, item := range strSlice {
		if _, ok := allKeys[item]; !ok {
			allKeys[item] = struct{}{}
			list = append(list, item)
		}
	}
	return list
}
