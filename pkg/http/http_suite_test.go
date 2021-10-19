package http

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var certData []byte
var certDataSource, keyDataSource options.SecretSource
var client *http.Client

func TestHTTPSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "HTTP")
}

var _ = BeforeSuite(func() {
	By("Generating a self-signed cert for TLS tests", func() {
		certBytes, keyData, err := util.GenerateCert()
		Expect(err).ToNot(HaveOccurred())
		certData = certBytes

		certOut := new(bytes.Buffer)
		Expect(pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})).To(Succeed())
		certDataSource.Value = certOut.Bytes()
		keyDataSource.Value = keyData
	})

	By("Setting up a http client", func() {
		cert, err := tls.X509KeyPair(certDataSource.Value, keyDataSource.Value)
		Expect(err).ToNot(HaveOccurred())

		certificate, err := x509.ParseCertificate(cert.Certificate[0])
		Expect(err).ToNot(HaveOccurred())

		certpool := x509.NewCertPool()
		certpool.AddCert(certificate)

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig.RootCAs = certpool

		client = &http.Client{
			Transport: transport,
		}
	})
})
