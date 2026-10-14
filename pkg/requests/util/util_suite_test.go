package util_test

import (
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// TestRequestUtilSuite and related tests are in a *_test package
// to prevent circular imports with the `logger` package which uses
// this functionality
func TestRequestUtilSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Request Utils")
}
