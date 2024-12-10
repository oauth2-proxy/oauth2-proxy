package redis

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"log"
	"os"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"
)

// wrappedRedisLogger wraps a logger so that we can coerce the logger to
// fit the expected signature for go-redis logging
type wrappedRedisLogger struct {
	*log.Logger
}

func (l *wrappedRedisLogger) Printf(_ context.Context, format string, v ...interface{}) {
	l.Logger.Printf(format, v...)
}

var (
	cert   tls.Certificate
	caPath string
)

func TestRedis(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	redisLogger := &wrappedRedisLogger{Logger: log.New(os.Stderr, "redis: ", log.LstdFlags|log.Lshortfile)}
	redisLogger.SetOutput(GinkgoWriter)
	redis.SetLogger(redisLogger)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Redis")
}

var _ = BeforeSuite(func() {
	var err error
	certBytes, keyBytes, err := util.GenerateCert("127.0.0.1")
	Expect(err).ToNot(HaveOccurred())
	certOut := new(bytes.Buffer)
	Expect(pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})).To(Succeed())
	certData := certOut.Bytes()
	keyOut := new(bytes.Buffer)
	Expect(pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})).To(Succeed())
	cert, err = tls.X509KeyPair(certData, keyOut.Bytes())
	Expect(err).ToNot(HaveOccurred())

	certFile, err := os.CreateTemp("", "cert.*.pem")
	Expect(err).ToNot(HaveOccurred())
	caPath = certFile.Name()
	_, err = certFile.Write(certData)
	defer certFile.Close()
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	Expect(os.Remove(caPath)).ToNot(HaveOccurred())
})
