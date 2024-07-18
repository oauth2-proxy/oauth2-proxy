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

var _ = BeforeSuite(func() {
	By("Generating a ipv4 self-signed cert for TLS tests", func() {
		certBytes, keyBytes, err := util.GenerateCert("127.0.0.1")
		Expect(err).ToNot(HaveOccurred())
		ipv4CertData = certBytes

		certOut := new(bytes.Buffer)
		Expect(pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})).To(Succeed())
		ipv4CertDataSource.Value = certOut.Bytes()
		keyOut := new(bytes.Buffer)
		Expect(pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})).To(Succeed())
		ipv4KeyDataSource.Value = keyOut.Bytes()
	})

	By("Generating a ipv6 self-signed cert for TLS tests", func() {
		certBytes, keyBytes, err := util.GenerateCert("::1")
		Expect(err).ToNot(HaveOccurred())
		ipv6CertData = certBytes

		certOut := new(bytes.Buffer)
		Expect(pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})).To(Succeed())
		ipv6CertDataSource.Value = certOut.Bytes()
		keyOut := new(bytes.Buffer)
		Expect(pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})).To(Succeed())
		ipv6KeyDataSource.Value = keyOut.Bytes()
	})

	By("Setting up a http client", func() {
		ipv4cert, err := tls.X509KeyPair(ipv4CertDataSource.Value, ipv4KeyDataSource.Value)
		Expect(err).ToNot(HaveOccurred())
		ipv6cert, err := tls.X509KeyPair(ipv6CertDataSource.Value, ipv6KeyDataSource.Value)
		Expect(err).ToNot(HaveOccurred())

		ipv4certificate, err := x509.ParseCertificate(ipv4cert.Certificate[0])
		Expect(err).ToNot(HaveOccurred())
		ipv6certificate, err := x509.ParseCertificate(ipv6cert.Certificate[0])
		Expect(err).ToNot(HaveOccurred())

		certpool := x509.NewCertPool()
		certpool.AddCert(ipv4certificate)
		certpool.AddCert(ipv6certificate)

		transport = http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig.RootCAs = certpool
	})
})
