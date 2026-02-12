package healthcheck

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHealthcheckSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Healthcheck")
}
