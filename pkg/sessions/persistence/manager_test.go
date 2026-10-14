package persistence

import (
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("Persistence Manager Tests", func() {
	var ms *tests.MockStore
	BeforeEach(func() {
		ms = tests.NewMockStore()
	})
	tests.RunSessionStoreTests(
		func(_ *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
			return NewManager(ms, cookieOpts), nil
		},
		func(d time.Duration) error {
			ms.FastForward(d)
			return nil
		})
})
