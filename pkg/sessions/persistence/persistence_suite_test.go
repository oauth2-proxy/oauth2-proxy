package persistence

import (
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPersistenceSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Persistence")
}
