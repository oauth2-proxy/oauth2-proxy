package authorization

import (
	"net/http"

	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Authorization Suite", func() {
	It("works", func() {
		req, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())

		session := &sessionsapi.SessionState{
			Email: "foo@bar.com",
		}

		authorized, err := authorize(req, session)
		Expect(err).ToNot(HaveOccurred())
		Expect(authorized).To(BeTrue())
	})
})
