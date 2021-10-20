package persistence

import (
	"context"
	"crypto/rand"
	"net/http/httptest"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo"
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

	Context("creating duplicate session key", func() {
		var m *Manager
		BeforeEach(func() {
			cookieSecret := make([]byte, 32)
			_, err := rand.Read(cookieSecret)
			Expect(err).ToNot(HaveOccurred())

			cookieOpts := &options.Cookie{
				Name:     "_oauth2_proxy",
				Path:     "/",
				Expire:   time.Duration(168) * time.Hour,
				Refresh:  time.Duration(1) * time.Hour,
				Secure:   true,
				HTTPOnly: true,
				SameSite: "",
				Secret:   string(cookieSecret),
			}

			m = NewManager(ms, cookieOpts)
		})

		It("returns an error", func() {
			// Setup mock func to return error
			ms.BeforeCreateFunc(func(c context.Context, key string, value []byte, exp time.Duration) error {
				return sessionsapi.ErrDuplicateSessionKey
			})

			expires := time.Now().Add(1 * time.Hour)
			session := &sessionsapi.SessionState{
				AccessToken: "AccessToken",
				IDToken:     "IDToken",
				ExpiresOn:   &expires,
			}

			req := httptest.NewRequest("GET", "http://example.com/", nil)
			saveResp := httptest.NewRecorder()
			err := m.Create(saveResp, req, session)
			Expect(err).To(MatchError(sessionsapi.ErrDuplicateSessionKey))
		})

		It("does not return an error by succeeding on retry", func() {
			// Setup mock func to return success on retry
			i := 0
			ms.BeforeCreateFunc(func(c context.Context, key string, value []byte, exp time.Duration) error {
				if i < 1 {
					i++
					return sessionsapi.ErrDuplicateSessionKey
				}
				return nil
			})

			expires := time.Now().Add(1 * time.Hour)
			session := &sessionsapi.SessionState{
				AccessToken: "AccessToken",
				IDToken:     "IDToken",
				ExpiresOn:   &expires,
			}

			req := httptest.NewRequest("GET", "http://example.com/", nil)
			saveResp := httptest.NewRecorder()
			err := m.Create(saveResp, req, session)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("updating with no existing session key", func() {
		var m *Manager
		BeforeEach(func() {
			cookieSecret := make([]byte, 32)
			_, err := rand.Read(cookieSecret)
			Expect(err).ToNot(HaveOccurred())

			cookieOpts := &options.Cookie{
				Name:     "_oauth2_proxy",
				Path:     "/",
				Expire:   time.Duration(168) * time.Hour,
				Refresh:  time.Duration(1) * time.Hour,
				Secure:   true,
				HTTPOnly: true,
				SameSite: "",
				Secret:   string(cookieSecret),
			}

			m = NewManager(ms, cookieOpts)
		})

		It("returns an error", func() {
			// Setup mock func to return error
			ms.BeforeUpdateFunc(func(c context.Context, key string, value []byte, exp time.Duration) error {
				return sessionsapi.ErrNotFoundSessionKey
			})

			expires := time.Now().Add(1 * time.Hour)
			session := &sessionsapi.SessionState{
				AccessToken: "AccessToken",
				IDToken:     "IDToken",
				ExpiresOn:   &expires,
			}

			req := httptest.NewRequest("GET", "http://example.com/", nil)
			saveResp := httptest.NewRecorder()
			err := m.Create(saveResp, req, session)
			Expect(err).ToNot(HaveOccurred())

			resultCookies := saveResp.Result().Cookies()
			for _, c := range resultCookies {
				req.AddCookie(c)
			}

			err = m.Update(saveResp, req, session)
			Expect(err).To(MatchError(sessionsapi.ErrNotFoundSessionKey))
		})
	})
})
