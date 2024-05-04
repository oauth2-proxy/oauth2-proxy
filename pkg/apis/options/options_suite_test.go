package options

import (
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
)

func TestOptionsSuite(t *testing.T) {
	// For comparing the full configuration differences of our structs we need to increase the gomega limits
	format.MaxLength = 0
	format.MaxDepth = 10

	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Options Suite")
}
