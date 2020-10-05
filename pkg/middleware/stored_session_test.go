package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stored Session Suite", func() {
	const (
		refresh   = "Refresh"
		noRefresh = "NoRefresh"
	)

	var ctx = context.Background()

	Context("StoredSessionLoader", func() {
		createdPast := time.Now().Add(-5 * time.Minute)
		createdFuture := time.Now().Add(5 * time.Minute)

		var defaultRefreshFunc = func(_ context.Context, ss *sessionsapi.SessionState) (bool, error) {
			switch ss.RefreshToken {
			case refresh:
				ss.RefreshToken = "Refreshed"
				return true, nil
			case noRefresh:
				return false, nil
			default:
				return false, errors.New("error refreshing session")
			}
		}

		var defaultValidateFunc = func(_ context.Context, ss *sessionsapi.SessionState) bool {
			return ss.AccessToken != "Invalid"
		}

		var defaultSessionStore = &fakeSessionStore{
			LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
				switch req.Header.Get("Cookie") {
				case "_oauth2_proxy=NoRefreshSession":
					return &sessionsapi.SessionState{
						RefreshToken: noRefresh,
						CreatedAt:    &createdPast,
						ExpiresOn:    &createdFuture,
					}, nil
				case "_oauth2_proxy=InvalidNoRefreshSession":
					return &sessionsapi.SessionState{
						AccessToken:  "Invalid",
						RefreshToken: noRefresh,
						CreatedAt:    &createdPast,
						ExpiresOn:    &createdFuture,
					}, nil
				case "_oauth2_proxy=ExpiredNoRefreshSession":
					return &sessionsapi.SessionState{
						RefreshToken: noRefresh,
						CreatedAt:    &createdPast,
						ExpiresOn:    &createdPast,
					}, nil
				case "_oauth2_proxy=RefreshSession":
					return &sessionsapi.SessionState{
						RefreshToken: refresh,
						CreatedAt:    &createdPast,
						ExpiresOn:    &createdFuture,
					}, nil
				case "_oauth2_proxy=RefreshError":
					return &sessionsapi.SessionState{
						RefreshToken: "RefreshError",
						CreatedAt:    &createdPast,
						ExpiresOn:    &createdFuture,
					}, nil
				case "_oauth2_proxy=NonExistent":
					return nil, fmt.Errorf("invalid cookie")
				default:
					return nil, nil
				}
			},
		}

		type storedSessionLoaderTableInput struct {
			requestHeaders  http.Header
			existingSession *sessionsapi.SessionState
			expectedSession *sessionsapi.SessionState
			store           sessionsapi.SessionStore
			refreshPeriod   time.Duration
			refreshSession  func(context.Context, *sessionsapi.SessionState) (bool, error)
			validateSession func(context.Context, *sessionsapi.SessionState) bool
		}

		DescribeTable("when serving a request",
			func(in storedSessionLoaderTableInput) {
				scope := &middlewareapi.RequestScope{
					Session: in.existingSession,
				}

				// Set up the request with the request headesr and a request scope
				req := httptest.NewRequest("", "/", nil)
				req.Header = in.requestHeaders
				contextWithScope := context.WithValue(req.Context(), requestScopeKey, scope)
				req = req.WithContext(contextWithScope)

				rw := httptest.NewRecorder()

				opts := &StoredSessionLoaderOptions{
					SessionStore:           in.store,
					RefreshPeriod:          in.refreshPeriod,
					RefreshSessionIfNeeded: in.refreshSession,
					ValidateSessionState:   in.validateSession,
				}

				// Create the handler with a next handler that will capture the session
				// from the scope
				var gotSession *sessionsapi.SessionState
				handler := NewStoredSessionLoader(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gotSession = r.Context().Value(requestScopeKey).(*middlewareapi.RequestScope).Session
				}))
				handler.ServeHTTP(rw, req)

				Expect(gotSession).To(Equal(in.expectedSession))
			},
			Entry("with no cookie", storedSessionLoaderTableInput{
				requestHeaders:  http.Header{},
				existingSession: nil,
				expectedSession: nil,
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("with an invalid cookie", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=NonExistent"},
				},
				existingSession: nil,
				expectedSession: nil,
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("with an existing session", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=RefreshSession"},
				},
				existingSession: &sessionsapi.SessionState{
					RefreshToken: "Existing",
				},
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: "Existing",
				},
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("with a session that has not expired", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=NoRefreshSession"},
				},
				existingSession: nil,
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
				},
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("with a session that cannot refresh and has expired", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=ExpiredNoRefreshSession"},
				},
				existingSession: nil,
				expectedSession: nil,
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("with a session that can refresh, but is younger than refresh period", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=RefreshSession"},
				},
				existingSession: nil,
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
				},
				store:           defaultSessionStore,
				refreshPeriod:   10 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("with a session that can refresh and is older than the refresh period", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=RefreshSession"},
				},
				existingSession: nil,
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: "Refreshed",
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
				},
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("when the provider refresh fails", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=RefreshError"},
				},
				existingSession: nil,
				expectedSession: nil,
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("when the session is not refreshed and is no longer valid", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=InvalidNoRefreshSession"},
				},
				existingSession: nil,
				expectedSession: nil,
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
		)
	})

	Context("refreshSessionIfNeeded", func() {
		type refreshSessionIfNeededTableInput struct {
			refreshPeriod   time.Duration
			session         *sessionsapi.SessionState
			expectedErr     error
			expectRefreshed bool
			expectValidated bool
		}

		createdPast := time.Now().Add(-5 * time.Minute)
		createdFuture := time.Now().Add(5 * time.Minute)

		DescribeTable("with a session",
			func(in refreshSessionIfNeededTableInput) {
				refreshed := false
				validated := false

				s := &storedSessionLoader{
					refreshPeriod: in.refreshPeriod,
					store:         &fakeSessionStore{},
					refreshSessionWithProviderIfNeeded: func(_ context.Context, ss *sessionsapi.SessionState) (bool, error) {
						refreshed = true
						switch ss.RefreshToken {
						case refresh:
							return true, nil
						case noRefresh:
							return false, nil
						default:
							return false, errors.New("error refreshing session")
						}
					},
					validateSessionState: func(_ context.Context, ss *sessionsapi.SessionState) bool {
						validated = true
						return ss.AccessToken != "Invalid"
					},
				}

				req := httptest.NewRequest("", "/", nil)
				err := s.refreshSessionIfNeeded(nil, req, in.session)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(refreshed).To(Equal(in.expectRefreshed))
				Expect(validated).To(Equal(in.expectValidated))
			},
			Entry("when the refresh period is 0, and the session does not need refreshing", refreshSessionIfNeededTableInput{
				refreshPeriod: time.Duration(0),
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdFuture,
				},
				expectedErr:     nil,
				expectRefreshed: false,
				expectValidated: false,
			}),
			Entry("when the refresh period is 0, and the session needs refreshing", refreshSessionIfNeededTableInput{
				refreshPeriod: time.Duration(0),
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
				},
				expectedErr:     nil,
				expectRefreshed: false,
				expectValidated: false,
			}),
			Entry("when the session does not need refreshing", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdFuture,
				},
				expectedErr:     nil,
				expectRefreshed: false,
				expectValidated: false,
			}),
			Entry("when the session is refreshed by the provider", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
				},
				expectedErr:     nil,
				expectRefreshed: true,
				expectValidated: false,
			}),
			Entry("when the session is not refreshed by the provider", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
				},
				expectedErr:     nil,
				expectRefreshed: true,
				expectValidated: true,
			}),
			Entry("when the provider refresh fails", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: "RefreshError",
					CreatedAt:    &createdPast,
				},
				expectedErr:     errors.New("error refreshing access token: error refreshing session"),
				expectRefreshed: true,
				expectValidated: false,
			}),
			Entry("when the session is not refreshed by the provider and validation fails", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					AccessToken:  "Invalid",
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
				},
				expectedErr:     errors.New("session is invalid"),
				expectRefreshed: true,
				expectValidated: true,
			}),
		)
	})

	Context("refreshSessionWithProvider", func() {
		type refreshSessionWithProviderTableInput struct {
			session         *sessionsapi.SessionState
			expectedErr     error
			expectRefreshed bool
			expectSaved     bool
		}

		now := time.Now()

		DescribeTable("when refreshing with the provider",
			func(in refreshSessionWithProviderTableInput) {
				saved := false

				s := &storedSessionLoader{
					store: &fakeSessionStore{
						SaveFunc: func(_ http.ResponseWriter, _ *http.Request, ss *sessionsapi.SessionState) error {
							saved = true
							if ss.AccessToken == "NoSave" {
								return errors.New("unable to save session")
							}
							return nil
						},
					},
					refreshSessionWithProviderIfNeeded: func(_ context.Context, ss *sessionsapi.SessionState) (bool, error) {
						switch ss.RefreshToken {
						case refresh:
							return true, nil
						case noRefresh:
							return false, nil
						default:
							return false, errors.New("error refreshing session")
						}
					},
				}

				req := httptest.NewRequest("", "/", nil)
				refreshed, err := s.refreshSessionWithProvider(nil, req, in.session)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(refreshed).To(Equal(in.expectRefreshed))
				Expect(saved).To(Equal(in.expectSaved))
			},
			Entry("when the provider does not refresh the session", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
				},
				expectedErr:     nil,
				expectRefreshed: false,
				expectSaved:     false,
			}),
			Entry("when the provider refreshes the session", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
				},
				expectedErr:     nil,
				expectRefreshed: true,
				expectSaved:     true,
			}),
			Entry("when the provider returns an error", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: "RefreshError",
					CreatedAt:    &now,
					ExpiresOn:    &now,
				},
				expectedErr:     errors.New("error refreshing access token: error refreshing session"),
				expectRefreshed: false,
				expectSaved:     false,
			}),
			Entry("when the saving the session returns an error", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					AccessToken:  "NoSave",
				},
				expectedErr:     errors.New("error saving session: unable to save session"),
				expectRefreshed: false,
				expectSaved:     true,
			}),
		)
	})

	Context("validateSession", func() {
		var s *storedSessionLoader

		BeforeEach(func() {
			s = &storedSessionLoader{
				validateSessionState: func(_ context.Context, ss *sessionsapi.SessionState) bool {
					return ss.AccessToken == "Valid"
				},
			}
		})

		Context("with a valid session", func() {
			It("does not return an error", func() {
				expires := time.Now().Add(1 * time.Minute)
				session := &sessionsapi.SessionState{
					AccessToken: "Valid",
					ExpiresOn:   &expires,
				}
				Expect(s.validateSession(ctx, session)).To(Succeed())
			})
		})

		Context("with an expired session", func() {
			It("returns an error", func() {
				created := time.Now().Add(-5 * time.Minute)
				expires := time.Now().Add(-1 * time.Minute)
				session := &sessionsapi.SessionState{
					AccessToken: "Valid",
					CreatedAt:   &created,
					ExpiresOn:   &expires,
				}
				Expect(s.validateSession(ctx, session)).To(MatchError("session is expired"))
			})
		})

		Context("with an invalid session", func() {
			It("returns an error", func() {
				expires := time.Now().Add(1 * time.Minute)
				session := &sessionsapi.SessionState{
					AccessToken: "Invalid",
					ExpiresOn:   &expires,
				}
				Expect(s.validateSession(ctx, session)).To(MatchError("session is invalid"))
			})
		})
	})
})

type fakeSessionStore struct {
	SaveFunc  func(http.ResponseWriter, *http.Request, *sessionsapi.SessionState) error
	LoadFunc  func(req *http.Request) (*sessionsapi.SessionState, error)
	ClearFunc func(rw http.ResponseWriter, req *http.Request) error
}

func (f *fakeSessionStore) Save(rw http.ResponseWriter, req *http.Request, s *sessionsapi.SessionState) error {
	if f.SaveFunc != nil {
		return f.SaveFunc(rw, req, s)
	}
	return nil
}
func (f *fakeSessionStore) Load(req *http.Request) (*sessionsapi.SessionState, error) {
	if f.LoadFunc != nil {
		return f.LoadFunc(req)
	}
	return nil, nil
}

func (f *fakeSessionStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	if f.ClearFunc != nil {
		return f.ClearFunc(rw, req)
	}
	return nil
}
