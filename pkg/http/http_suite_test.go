package http

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
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
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())

		keyOut := bytes.NewBuffer(nil)
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		Expect(err).ToNot(HaveOccurred())
		Expect(pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})).To(Succeed())
		keyDataSource.Value = keyOut.Bytes()

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		Expect(err).ToNot(HaveOccurred())

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"OAuth2 Proxy Test Suite"},
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(time.Hour),
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		Expect(err).ToNot(HaveOccurred())
		certData = certBytes

		certOut := bytes.NewBuffer(nil)
		Expect(pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})).To(Succeed())
		certDataSource.Value = certOut.Bytes()
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
