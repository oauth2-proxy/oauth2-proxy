package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var ipv4Addr, ipv6Addr = "127.0.0.1", "::1"
var ipv4CertData, ipv6CertData []byte
var ipv4CertDataSource, ipv4KeyDataSource options.SecretSource
var ipv6CertDataSource, ipv6KeyDataSource options.SecretSource
var transport *http.Transport

func TestHTTPSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "HTTP")
}

func httpGet(ctx context.Context, url string) (*http.Response, error) {
	c := &http.Client{
		Transport: transport.Clone(),
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func generateCert(ipaddr string) (certData, certOutBytes, keyOutBytes []byte, err error) {
	certBytes, keyBytes, err := util.GenerateCert(ipaddr)
	if err != nil {
		return
	}
	certData = certBytes

	certOut := new(bytes.Buffer)
	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return
	}
	certOutBytes = certOut.Bytes()

	keyOut := new(bytes.Buffer)
	if err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return
	}
	keyOutBytes = keyOut.Bytes()

	return
}

func generateX509Cert(certSource, keySource options.SecretSource) (*x509.Certificate, error) {
	cert, err := tls.X509KeyPair(certSource.Value, keySource.Value)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return certificate, nil
}

func addCertToTransportRootCAs(transport *http.Transport, cert ...*x509.Certificate) {
	transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	for _, c := range cert {
		transport.TLSClientConfig.RootCAs.AddCert(c)
	}
}

var _ = BeforeSuite(func() {
	By("Generating a ipv4 self-signed cert for TLS tests", func() {
		ipv4Cert, ipv4CertBytes, ipv4KeyBytes, err := generateCert(ipv4Addr)
		Expect(err).ToNot(HaveOccurred())

		ipv4CertData, ipv4CertDataSource.Value, ipv4KeyDataSource.Value = ipv4Cert, ipv4CertBytes, ipv4KeyBytes
	})

	By("Generating a ipv6 self-signed cert for TLS tests", func() {
		ipv6Cert, ipv6CertBytes, ipv6KeyBytes, err := generateCert(ipv6Addr)
		Expect(err).ToNot(HaveOccurred())

		ipv6CertData, ipv6CertDataSource.Value, ipv6KeyDataSource.Value = ipv6Cert, ipv6CertBytes, ipv6KeyBytes
	})

	By("Setting up a http client", func() {
		ipv4certificate, err := generateX509Cert(ipv4CertDataSource, ipv4KeyDataSource)
		Expect(err).ToNot(HaveOccurred())

		ipv6certificate, err := generateX509Cert(ipv6CertDataSource, ipv6KeyDataSource)
		Expect(err).ToNot(HaveOccurred())

		transport = http.DefaultTransport.(*http.Transport).Clone()
		addCertToTransportRootCAs(transport, ipv4certificate, ipv6certificate)
	})
})
