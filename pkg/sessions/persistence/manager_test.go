package persistence

import (
	"context"
	"net/http/httptest"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

	Describe("ClearBySID", func() {
		var (
			manager    *Manager
			cookieOpts *options.Cookie
		)

		BeforeEach(func() {
			ms = tests.NewMockStore()
			cookieOpts = &options.Cookie{
				Name:   "_oauth2_proxy",
				Expire: time.Hour,
			}
			manager = NewManager(ms, cookieOpts)
		})

		It("clears the session and SID index when a valid SID is given", func() {
			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)

			session := &sessionsapi.SessionState{
				Email:     "user@example.com",
				SessionID: "test-sid-1234",
			}
			Expect(manager.Save(rw, req, session)).To(Succeed())
			// After save: session data + SID index = 2 entries
			Expect(ms.CacheSize()).To(Equal(2))

			Expect(manager.ClearBySID(context.Background(), "test-sid-1234")).To(Succeed())
			// Both entries should be gone
			Expect(ms.CacheSize()).To(Equal(0))
		})

		It("returns an error when the SID is not found", func() {
			err := manager.ClearBySID(context.Background(), "nonexistent-sid")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no session found for sid"))
		})

		It("does not write a SID index when SessionID is empty", func() {
			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)

			session := &sessionsapi.SessionState{
				Email: "user@example.com",
				// SessionID intentionally empty
			}
			Expect(manager.Save(rw, req, session)).To(Succeed())
			// Only session data, no SID index
			Expect(ms.CacheSize()).To(Equal(1))
		})
	})
})
