package tests

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	cookiesapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/cookies"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// testInput is passed to test function as a pointer.
// This allows BeforeEach blocks to initialise and use these values after
// Ginkgo has unpacked the tests.
// Interfaces have to be wrapped in closures otherwise nil pointers are thrown.
type testInput struct {
	cookieOpts            *options.Cookie
	ss                    sessionStoreFunc
	session               *sessionsapi.SessionState
	request               *http.Request
	response              *httptest.ResponseRecorder
	persistentFastForward PersistentStoreFastForwardFunc
}

// sessionStoreFunc is used in testInput to wrap the SessionStore interface.
type sessionStoreFunc func() sessionsapi.SessionStore

// PersistentStoreFastForwardFunc is used to adjust the time of the persistent
// store to fast forward expiry of sessions.
type PersistentStoreFastForwardFunc func(time.Duration) error

// NewSessionStoreFunc allows any session store implementation to configure their
// own session store before each test.
type NewSessionStoreFunc func(sessionOpts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error)

func RunSessionStoreTests(newSS NewSessionStoreFunc, persistentFastForward PersistentStoreFastForwardFunc) {
	Describe("Session Store Suite", func() {
		var opts *options.SessionOptions
		var ss sessionsapi.SessionStore
		var input testInput
		var cookieSecret []byte

		getSessionStore := func() sessionsapi.SessionStore {
			return ss
		}

		BeforeEach(func() {
			ss = nil
			opts = &options.SessionOptions{}

			// A secret is required to create a Cipher, validation ensures it is the correct
			// length before a session store is initialised.
			cookieSecret = make([]byte, 32)
			_, err := rand.Read(cookieSecret)
			Expect(err).ToNot(HaveOccurred())

			// Set default options in CookieOptions
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

			expires := time.Now().Add(1 * time.Hour)
			session := &sessionsapi.SessionState{
				AccessToken:  "AccessToken",
				IDToken:      "IDToken",
				ExpiresOn:    &expires,
				RefreshToken: "RefreshToken",
				Email:        "john.doe@example.com",
				User:         "john.doe",
			}

			request := httptest.NewRequest("GET", "http://example.com/", nil)
			response := httptest.NewRecorder()

			input = testInput{
				cookieOpts:            cookieOpts,
				ss:                    getSessionStore,
				session:               session,
				request:               request,
				response:              response,
				persistentFastForward: persistentFastForward,
			}
		})

		Context("with default options", func() {
			BeforeEach(func() {
				var err error
				ss, err = newSS(opts, input.cookieOpts)
				Expect(err).ToNot(HaveOccurred())
			})

			SessionStoreInterfaceTests(&input)
			if persistentFastForward != nil {
				PersistentSessionStoreInterfaceTests(&input)
			}
		})

		Context("with non-default options", func() {
			BeforeEach(func() {
				input.cookieOpts = &options.Cookie{
					Name:     "_cookie_name",
					Path:     "/path",
					Expire:   time.Duration(72) * time.Hour,
					Refresh:  time.Duration(2) * time.Hour,
					Secure:   false,
					HTTPOnly: false,
					Domains:  []string{"example.com"},
					SameSite: "strict",
					Secret:   string(cookieSecret),
				}

				var err error
				ss, err = newSS(opts, input.cookieOpts)
				Expect(err).ToNot(HaveOccurred())
			})

			SessionStoreInterfaceTests(&input)
			if persistentFastForward != nil {
				PersistentSessionStoreInterfaceTests(&input)
			}
		})
	})
}

func CheckCookieOptions(in *testInput) {
	Context("the cookies returned", func() {
		var cookies []*http.Cookie
		BeforeEach(func() {
			cookies = in.response.Result().Cookies()
		})

		It("have the correct name set", func() {
			if len(cookies) == 1 {
				Expect(cookies[0].Name).To(Equal(in.cookieOpts.Name))
			} else {
				for _, cookie := range cookies {
					Expect(cookie.Name).To(ContainSubstring(in.cookieOpts.Name))
				}
			}
		})

		It("have the correct path set", func() {
			for _, cookie := range cookies {
				Expect(cookie.Path).To(Equal(in.cookieOpts.Path))
			}
		})

		It("have the correct domain set", func() {
			for _, cookie := range cookies {
				specifiedDomain := ""
				if len(in.cookieOpts.Domains) > 0 {
					specifiedDomain = in.cookieOpts.Domains[0]
				}
				Expect(cookie.Domain).To(Equal(specifiedDomain))
			}
		})

		It("have the correct HTTPOnly set", func() {
			for _, cookie := range cookies {
				Expect(cookie.HttpOnly).To(Equal(in.cookieOpts.HTTPOnly))
			}
		})

		It("have the correct secure set", func() {
			for _, cookie := range cookies {
				Expect(cookie.Secure).To(Equal(in.cookieOpts.Secure))
			}
		})

		It("have the correct SameSite set", func() {
			for _, cookie := range cookies {
				Expect(cookie.SameSite).To(Equal(cookiesapi.ParseSameSite(in.cookieOpts.SameSite)))
			}
		})

		It("have a signature timestamp matching session.CreatedAt", func() {
			for _, cookie := range cookies {
				if cookie.Value != "" {
					parts := strings.Split(cookie.Value, "|")
					Expect(parts).To(HaveLen(3))
					Expect(parts[1]).To(Equal(strconv.Itoa(int(in.session.CreatedAt.Unix()))))
				}
			}
		})

	})
}

func PersistentSessionStoreInterfaceTests(in *testInput) {
	// Check that a stale cookie can't load an already cleared session
	Context("when Clear is called on a persistent store", func() {
		var resultCookies []*http.Cookie

		BeforeEach(func() {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			saveResp := httptest.NewRecorder()
			err := in.ss().Save(saveResp, req, in.session)
			Expect(err).ToNot(HaveOccurred())

			resultCookies = saveResp.Result().Cookies()
			for _, c := range resultCookies {
				in.request.AddCookie(c)
			}
			err = in.ss().Clear(in.response, in.request)
			Expect(err).ToNot(HaveOccurred())
		})

		Context("attempting to Load", func() {
			var loadedAfterClear *sessionsapi.SessionState
			var loadErr error

			BeforeEach(func() {
				loadReq := httptest.NewRequest("GET", "http://example.com/", nil)
				for _, c := range resultCookies {
					loadReq.AddCookie(c)
				}

				loadedAfterClear, loadErr = in.ss().Load(loadReq)
			})

			It("returns an empty session", func() {
				Expect(loadedAfterClear).To(BeNil())
			})

			It("returns an error", func() {
				Expect(loadErr).To(HaveOccurred())
			})
		})

		CheckCookieOptions(in)
	})

	// Test TTLs and cleanup of persistent session storage
	// For non-persistent we rely on the browser cookie lifecycle
	Context("when Load is called on a persistent store", func() {
		BeforeEach(func() {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			resp := httptest.NewRecorder()
			err := in.ss().Save(resp, req, in.session)
			Expect(err).ToNot(HaveOccurred())

			for _, cookie := range resp.Result().Cookies() {
				in.request.AddCookie(cookie)
			}
		})

		Context("after the refresh period, but before the cookie expire period", func() {
			BeforeEach(func() {
				Expect(in.persistentFastForward(in.cookieOpts.Refresh + time.Minute)).To(Succeed())
			})

			LoadSessionTests(in)
		})

		Context("after the cookie expire period", func() {
			var loadedSession *sessionsapi.SessionState
			var err error

			BeforeEach(func() {
				Expect(in.persistentFastForward(in.cookieOpts.Expire + time.Minute)).To(Succeed())

				loadedSession, err = in.ss().Load(in.request)
				Expect(err).To(HaveOccurred())
			})

			It("returns an error loading the session", func() {
				Expect(err).To(HaveOccurred())
			})

			It("returns an empty session", func() {
				Expect(loadedSession).To(BeNil())
			})
		})
	})

	Context("when lock is applied", func() {
		var loadedSession *sessionsapi.SessionState
		BeforeEach(func() {
			resp := httptest.NewRecorder()
			err := in.ss().Save(resp, in.request, in.session)
			Expect(err).ToNot(HaveOccurred())

			for _, cookie := range resp.Result().Cookies() {
				in.request.AddCookie(cookie)
			}

			loadedSession, err = in.ss().Load(in.request)
			Expect(err).ToNot(HaveOccurred())
			err = loadedSession.ObtainLock(in.request.Context(), 2*time.Minute)
			Expect(err).ToNot(HaveOccurred())
			isLocked, err := loadedSession.PeekLock(in.request.Context())
			Expect(err).ToNot(HaveOccurred())
			Expect(isLocked).To(BeTrue())
		})

		Context("before lock expired", func() {
			BeforeEach(func() {
				Expect(in.persistentFastForward(time.Minute)).To(Succeed())
			})

			It("peek returns true on loaded session lock", func() {
				l := *loadedSession
				isLocked, err := l.PeekLock(in.request.Context())

				Expect(err).NotTo(HaveOccurred())
				Expect(isLocked).To(BeTrue())
			})

			It("lock can be released", func() {
				l := *loadedSession

				err := l.ReleaseLock(in.request.Context())
				Expect(err).NotTo(HaveOccurred())

				isLocked, err := l.PeekLock(in.request.Context())
				Expect(err).NotTo(HaveOccurred())
				Expect(isLocked).To(BeFalse())
			})

			It("lock is refreshed", func() {
				l := *loadedSession
				err := l.RefreshLock(in.request.Context(), 3*time.Minute)
				Expect(err).NotTo(HaveOccurred())

				Expect(in.persistentFastForward(2 * time.Minute)).To(Succeed())

				isLocked, err := l.PeekLock(in.request.Context())
				Expect(err).NotTo(HaveOccurred())
				Expect(isLocked).To(BeTrue())
			})
		})

		Context("after lock expired", func() {
			BeforeEach(func() {
				Expect(in.persistentFastForward(3 * time.Minute)).To(Succeed())
			})

			It("peek returns false on loaded session lock", func() {
				l := *loadedSession
				isLocked, err := l.PeekLock(in.request.Context())

				Expect(err).NotTo(HaveOccurred())
				Expect(isLocked).To(BeFalse())
			})
		})
	})
}

func SessionStoreInterfaceTests(in *testInput) {
	Context("when Save is called", func() {
		Context("with no existing session", func() {
			BeforeEach(func() {
				err := in.ss().Save(in.response, in.request, in.session)
				Expect(err).ToNot(HaveOccurred())
			})

			It("sets a `set-cookie` header in the response", func() {
				Expect(in.response.Header().Get("set-cookie")).ToNot(BeEmpty())
			})

			It("Ensures the session CreatedAt is not zero", func() {
				Expect(in.session.CreatedAt.IsZero()).To(BeFalse())
			})

			CheckCookieOptions(in)
		})

		Context("with a broken session", func() {
			BeforeEach(func() {
				By("Using a valid cookie with a different providers session encoding")
				broken := "BrokenSessionFromADifferentSessionImplementation"
				value, err := encryption.SignedValue(in.cookieOpts.Secret, in.cookieOpts.Name, []byte(broken), time.Now())
				Expect(err).ToNot(HaveOccurred())
				cookie := cookiesapi.MakeCookieFromOptions(in.request, in.cookieOpts.Name, value, in.cookieOpts, in.cookieOpts.Expire, time.Now())
				in.request.AddCookie(cookie)

				err = in.ss().Save(in.response, in.request, in.session)
				Expect(err).ToNot(HaveOccurred())
			})

			It("sets a `set-cookie` header in the response", func() {
				Expect(in.response.Header().Get("set-cookie")).ToNot(BeEmpty())
			})

			It("Ensures the session CreatedAt is not zero", func() {
				Expect(in.session.CreatedAt.IsZero()).To(BeFalse())
			})

			CheckCookieOptions(in)
		})

		Context("with an expired saved session", func() {
			var err error
			BeforeEach(func() {
				By("saving a session")
				req := httptest.NewRequest("GET", "http://example.com/", nil)
				saveResp := httptest.NewRecorder()
				err = in.ss().Save(saveResp, req, in.session)
				Expect(err).ToNot(HaveOccurred())

				By("and clearing the session")
				for _, c := range saveResp.Result().Cookies() {
					in.request.AddCookie(c)
				}
				clearResp := httptest.NewRecorder()
				err = in.ss().Clear(clearResp, in.request)
				Expect(err).ToNot(HaveOccurred())

				By("then saving a request with the cleared session")
				err = in.ss().Save(in.response, in.request, in.session)
			})

			It("no error should occur", func() {
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Context("when Clear is called", func() {
		BeforeEach(func() {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			saveResp := httptest.NewRecorder()
			err := in.ss().Save(saveResp, req, in.session)
			Expect(err).ToNot(HaveOccurred())

			for _, c := range saveResp.Result().Cookies() {
				in.request.AddCookie(c)
			}
			err = in.ss().Clear(in.response, in.request)
			Expect(err).ToNot(HaveOccurred())
		})

		It("sets a `set-cookie` header in the response", func() {
			Expect(in.response.Header().Get("Set-Cookie")).ToNot(BeEmpty())
		})

		CheckCookieOptions(in)
	})

	Context("when Load is called", func() {
		Context("with a valid session cookie in the request", func() {
			BeforeEach(func() {
				req := httptest.NewRequest("GET", "http://example.com/", nil)
				resp := httptest.NewRecorder()
				err := in.ss().Save(resp, req, in.session)
				Expect(err).ToNot(HaveOccurred())
				for _, cookie := range resp.Result().Cookies() {
					in.request.AddCookie(cookie)
				}
			})

			Context("before the refresh period", func() {
				LoadSessionTests(in)
			})
		})

		Context("with no cookies in the request", func() {
			var loadedSession *sessionsapi.SessionState
			var loadErr error

			BeforeEach(func() {
				loadedSession, loadErr = in.ss().Load(in.request)
			})

			It("returns an empty session", func() {
				Expect(loadedSession).To(BeNil())
			})

			It("should return a no cookie error", func() {
				Expect(loadErr).To(MatchError(http.ErrNoCookie))
			})
		})
	})

	Context("when VerifyConnection is called", func() {
		It("should return without an error", func() {
			Expect(in.ss().VerifyConnection(in.request.Context())).ToNot(HaveOccurred())
		})
	})
}

func LoadSessionTests(in *testInput) {
	var loadedSession *sessionsapi.SessionState
	BeforeEach(func() {
		var err error
		loadedSession, err = in.ss().Load(in.request)
		Expect(err).ToNot(HaveOccurred())
	})

	It("loads a session equal to the original session", func() {
		// Can't compare time.Time using Equal() so remove ExpiresOn from sessions
		l := *loadedSession
		l.CreatedAt = nil
		l.ExpiresOn = nil
		l.Lock = &sessionsapi.NoOpLock{}
		s := *in.session
		s.CreatedAt = nil
		s.ExpiresOn = nil
		s.Lock = &sessionsapi.NoOpLock{}
		Expect(l).To(Equal(s))

		// Compare time.Time separately
		Expect(loadedSession.CreatedAt.Equal(*in.session.CreatedAt)).To(BeTrue())
		Expect(loadedSession.ExpiresOn.Equal(*in.session.ExpiresOn)).To(BeTrue())

	})
}
