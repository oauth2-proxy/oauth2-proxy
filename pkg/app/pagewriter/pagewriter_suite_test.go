package pagewriter

import (
	"log/slog"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const testRequestID = "11111111-2222-4333-8444-555555555555"

func TestOptionsSuite(t *testing.T) {
	logger.Setup(slog.LevelDebug, "text", GinkgoWriter, GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "App Suite")
}
