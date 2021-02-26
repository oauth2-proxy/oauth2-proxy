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
		refresh      = "Refresh"
		noRefresh    = "NoRefresh"
		refreshError = "RefreshError"
	)

	var ctx = context.Background()

	Context("StoredSessionLoader", func() {
		createdPast := time.Now().Add(-5 * time.Minute)
		createdFuture := time.Now().Add(5 * time.Minute)

		var defaultRefreshFunc = func(_ context.Context, ss *sessionsapi.SessionState) error {
			switch ss.RefreshToken {
			case refresh:
				ss.RefreshToken = "Refreshed"
				return nil
			case noRefresh:
				return nil
			default:
				return errors.New("error refreshing validSession")
			}
		}

		var defaultIsRefreshNeededFunc = func(ss *sessionsapi.SessionState) bool {
			switch ss.RefreshToken {
			case refresh:
				return true
			case noRefresh:
				return false
			case refreshError:
				return true
			default:
				return false
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
						RefreshToken: refreshError,
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
			requestHeaders         http.Header
			existingSession        *sessionsapi.SessionState
			expectedSession        *sessionsapi.SessionState
			store                  sessionsapi.SessionStore
			refreshPeriod          time.Duration
			refreshSession         func(context.Context, *sessionsapi.SessionState) error
			isRefreshSessionNeeded func(*sessionsapi.SessionState) bool
			validateSession        func(context.Context, *sessionsapi.SessionState) bool
		}

		DescribeTable("when serving a request",
			func(in storedSessionLoaderTableInput) {
				scope := &middlewareapi.RequestScope{
					Session: in.existingSession,
				}

				// Set up the request with the request header and a request scope
				req := httptest.NewRequest("", "/", nil)
				req.Header = in.requestHeaders
				req = middlewareapi.AddRequestScope(req, scope)

				rw := httptest.NewRecorder()

				opts := &StoredSessionLoaderOptions{
					SessionStore:           in.store,
					RefreshPeriod:          in.refreshPeriod,
					RefreshSession:         in.refreshSession,
					IsRefreshSessionNeeded: in.isRefreshSessionNeeded,
					ValidateSessionState:   in.validateSession,
				}

				// Create the handler with a next handler that will capture the validSession
				// from the scope
				var gotSession *sessionsapi.SessionState
				handler := NewStoredSessionLoader(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gotSession = middlewareapi.GetRequestScope(r).Session
				}))
				handler.ServeHTTP(rw, req)

				Expect(gotSession).To(Equal(in.expectedSession))
			},
			Entry("with no cookie", storedSessionLoaderTableInput{
				requestHeaders:         http.Header{},
				existingSession:        nil,
				expectedSession:        nil,
				store:                  defaultSessionStore,
				refreshPeriod:          1 * time.Minute,
				refreshSession:         defaultRefreshFunc,
				isRefreshSessionNeeded: defaultIsRefreshNeededFunc,
				validateSession:        defaultValidateFunc,
			}),
			Entry("with an invalid cookie", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=NonExistent"},
				},
				existingSession:        nil,
				expectedSession:        nil,
				store:                  defaultSessionStore,
				refreshPeriod:          1 * time.Minute,
				refreshSession:         defaultRefreshFunc,
				isRefreshSessionNeeded: defaultIsRefreshNeededFunc,
				validateSession:        defaultValidateFunc,
			}),
			Entry("with an existing validSession", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=RefreshSession"},
				},
				existingSession: &sessionsapi.SessionState{
					RefreshToken: "Existing",
				},
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: "Existing",
				},
				store:                  defaultSessionStore,
				refreshPeriod:          1 * time.Minute,
				refreshSession:         defaultRefreshFunc,
				isRefreshSessionNeeded: defaultIsRefreshNeededFunc,
				validateSession:        defaultValidateFunc,
			}),
			Entry("with a validSession that has not expired", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=NoRefreshSession"},
				},
				existingSession: nil,
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
				},
				store:                  defaultSessionStore,
				refreshPeriod:          1 * time.Minute,
				refreshSession:         defaultRefreshFunc,
				isRefreshSessionNeeded: defaultIsRefreshNeededFunc,
				validateSession:        defaultValidateFunc,
			}),
			Entry("with a validSession that cannot refresh and has expired", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=ExpiredNoRefreshSession"},
				},
				existingSession:        nil,
				expectedSession:        nil,
				store:                  defaultSessionStore,
				refreshPeriod:          1 * time.Minute,
				refreshSession:         defaultRefreshFunc,
				isRefreshSessionNeeded: defaultIsRefreshNeededFunc,
				validateSession:        defaultValidateFunc,
			}),
			Entry("with a validSession that can refresh, but is younger than refresh period", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=RefreshSession"},
				},
				existingSession: nil,
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
				},
				store:                  defaultSessionStore,
				refreshPeriod:          10 * time.Minute,
				refreshSession:         defaultRefreshFunc,
				isRefreshSessionNeeded: defaultIsRefreshNeededFunc,
				validateSession:        defaultValidateFunc,
			}),
			Entry("with a validSession that can refresh and is older than the refresh period", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=RefreshSession"},
				},
				existingSession: nil,
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: "Refreshed",
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
				},
				store:                  defaultSessionStore,
				refreshPeriod:          1 * time.Minute,
				refreshSession:         defaultRefreshFunc,
				isRefreshSessionNeeded: defaultIsRefreshNeededFunc,
				validateSession:        defaultValidateFunc,
			}),
			Entry("when the provider refresh fails", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=RefreshError"},
				},
				existingSession:        nil,
				expectedSession:        nil,
				store:                  defaultSessionStore,
				refreshPeriod:          1 * time.Minute,
				refreshSession:         defaultRefreshFunc,
				isRefreshSessionNeeded: defaultIsRefreshNeededFunc,
				validateSession:        defaultValidateFunc,
			}),
			Entry("when the validSession is not refreshed and is no longer valid", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=InvalidNoRefreshSession"},
				},
				existingSession:        nil,
				expectedSession:        nil,
				store:                  defaultSessionStore,
				refreshPeriod:          1 * time.Minute,
				refreshSession:         defaultRefreshFunc,
				isRefreshSessionNeeded: defaultIsRefreshNeededFunc,
				validateSession:        defaultValidateFunc,
			}),
		)
	})

	Context("ensureSessionIsValid", func() {
		type ensureSessionIsValidTableInput struct {
			refreshPeriod   time.Duration
			session         *sessionsapi.SessionState
			expectedErr     error
			expectRefreshed bool
			expectValidated bool
		}

		createdPast := time.Now().Add(-5 * time.Minute)
		createdFuture := time.Now().Add(5 * time.Minute)

		DescribeTable("with a validSession",
			func(in ensureSessionIsValidTableInput) {
				refreshed := false
				validated := false

				s := &storedSessionLoader{
					refreshPeriod: in.refreshPeriod,
					store: &fakeSessionStore{
						LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
							return in.session, nil
						},
					},
					refreshSessionWithProvider: func(_ context.Context, ss *sessionsapi.SessionState) error {
						switch ss.RefreshToken {
						case refresh:
							refreshed = true
							return nil
						case noRefresh:
							return nil
						default:
							return errors.New("error refreshing validSession")
						}
					},
					isRefreshSessionNeededWithProvider: func(ss *sessionsapi.SessionState) bool {
						switch ss.RefreshToken {
						case refresh:
							return true
						case noRefresh:
							return false
						case refreshError:
							return true
						default:
							return false
						}
					},
					validateSessionState: func(_ context.Context, ss *sessionsapi.SessionState) bool {
						validated = true
						return ss.AccessToken != "Invalid"
					},
				}

				req := httptest.NewRequest("", "/", nil)
				_, err := s.ensureSessionIsValid(nil, req, in.session)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(refreshed).To(Equal(in.expectRefreshed))
				Expect(validated).To(Equal(in.expectValidated))
			},
			Entry("when the refresh period is 0, and the validSession does not need refreshing", ensureSessionIsValidTableInput{
				refreshPeriod: time.Duration(0),
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdFuture,
				},
				expectedErr:     nil,
				expectRefreshed: false,
				expectValidated: false,
			}),
			Entry("when the refresh period is 0, and the validSession needs refreshing", ensureSessionIsValidTableInput{
				refreshPeriod: time.Duration(0),
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
				},
				expectedErr:     nil,
				expectRefreshed: false,
				expectValidated: false,
			}),
			Entry("when the validSession does not need refreshing", ensureSessionIsValidTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdFuture,
				},
				expectedErr:     nil,
				expectRefreshed: false,
				expectValidated: false,
			}),
			Entry("when the validSession is refreshed by the provider", ensureSessionIsValidTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
				},
				expectedErr:     nil,
				expectRefreshed: true,
				expectValidated: false,
			}),
			Entry("when the validSession is not refreshed by the provider", ensureSessionIsValidTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
				},
				expectedErr:     nil,
				expectRefreshed: false,
				expectValidated: true,
			}),
			Entry("when the provider refresh fails", ensureSessionIsValidTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: refreshError,
					CreatedAt:    &createdPast,
				},
				expectedErr: errors.New(
					fmt.Sprintf("error refreshing access token for validSession (%s): error refreshing access token: error refreshing validSession",
						&sessionsapi.SessionState{
							RefreshToken: refreshError,
							CreatedAt:    &createdPast,
						})),
				expectRefreshed: false,
				expectValidated: false,
			}),
			Entry("when the validSession is not refreshed by the provider and validation fails", ensureSessionIsValidTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					AccessToken:  "Invalid",
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
				},
				expectedErr:     errors.New("validSession is invalid"),
				expectRefreshed: false,
				expectValidated: true,
			}),
		)
	})

	Context("retryLoadingValidSession", func() {
		type retryLoadingValidSessionTableInput struct {
			validSession        *sessionsapi.SessionState
			inValidSession      *sessionsapi.SessionState
			maxAttempts         int
			attemptValidSession int
			expectedErr         error
		}

		createdFuture := time.Now().Add(5 * time.Minute)
		createdPast := time.Now().Add(-5 * time.Minute)

		DescribeTable("when invalid session is replaces with valid",
			func(in retryLoadingValidSessionTableInput) {
				attempt := 0
				s := &storedSessionLoader{
					refreshPeriod: 1,
					store: &fakeSessionStore{
						LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
							if in.expectedErr != nil {
								return nil, in.expectedErr
							}
							attempt++
							if in.attemptValidSession == attempt {
								return in.validSession, nil
							}
							return in.inValidSession, nil
						},
					},
					isRefreshSessionNeededWithProvider: func(session *sessionsapi.SessionState) bool {
						return true
					},
				}

				req := httptest.NewRequest("", "/", nil)
				session, err := s.retryLoadingValidSession(req, in.maxAttempts)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
					Expect(session).To(Equal(in.validSession))
				}
			},
			Entry("load valid session with first attempt", retryLoadingValidSessionTableInput{
				maxAttempts:         10,
				attemptValidSession: 1,
				validSession: &sessionsapi.SessionState{
					CreatedAt: &createdFuture,
				},
				inValidSession: nil,
				expectedErr:    nil,
			}),
			Entry("load valid session with second attempt", retryLoadingValidSessionTableInput{
				maxAttempts:         10,
				attemptValidSession: 2,
				validSession: &sessionsapi.SessionState{
					CreatedAt: &createdFuture,
				},
				inValidSession: &sessionsapi.SessionState{
					CreatedAt: &createdPast,
				},
				expectedErr: nil,
			}),
			Entry("load session when error occurred", retryLoadingValidSessionTableInput{
				maxAttempts:         10,
				attemptValidSession: 0,
				validSession:        nil,
				inValidSession:      nil,
				expectedErr:         errors.New("not able to load valid session"),
			}),
		)
	})

	Context("isRefreshPeriodOver", func() {
		type isRefreshPeriodOverTableInput struct {
			refreshPeriod    time.Duration
			session          *sessionsapi.SessionState
			expectPeriodOver bool
		}

		createdPast := time.Now().Add(-5 * time.Minute)

		DescribeTable("with a validSession",
			func(in isRefreshPeriodOverTableInput) {
				s := &storedSessionLoader{
					refreshPeriod: in.refreshPeriod,
				}

				periodIsOver := s.isRefreshPeriodOver(in.session)
				Expect(periodIsOver).To(Equal(in.expectPeriodOver))
			},
			Entry("when the refresh period is 0, and the validSession does not need refreshing", isRefreshPeriodOverTableInput{
				refreshPeriod: time.Duration(0),
				session: &sessionsapi.SessionState{
					CreatedAt: &createdPast,
				},
				expectPeriodOver: false,
			}),
			Entry("when the refresh period is 1, and the validSession need refreshing", isRefreshPeriodOverTableInput{
				refreshPeriod: time.Duration(1),
				session: &sessionsapi.SessionState{
					CreatedAt: &createdPast,
				},
				expectPeriodOver: true,
			}),
			Entry("when the refresh period is 6, and the validSession does not need refreshing", isRefreshPeriodOverTableInput{
				refreshPeriod: 6 * time.Minute,
				session: &sessionsapi.SessionState{
					CreatedAt: &createdPast,
				},
				expectPeriodOver: false,
			}),
		)
	})

	Context("refreshSession", func() {
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
				refreshed := false

				s := &storedSessionLoader{
					store: &fakeSessionStore{
						SaveFunc: func(_ http.ResponseWriter, _ *http.Request, ss *sessionsapi.SessionState) error {
							saved = true
							if ss.AccessToken == "NoSave" {
								return errors.New("unable to save validSession")
							}
							return nil
						},
						LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
							return in.session, nil
						},
					},
					refreshSessionWithProvider: func(_ context.Context, ss *sessionsapi.SessionState) error {
						switch ss.RefreshToken {
						case refresh:
							refreshed = true
							return nil
						case noRefresh:
							return nil
						case refreshError:
							return errors.New("error refreshing validSession")
						default:
							return nil
						}
					},
					isRefreshSessionNeededWithProvider: func(ss *sessionsapi.SessionState) bool {
						switch ss.RefreshToken {
						case refresh:
							return true
						case noRefresh:
							return false
						case refreshError:
							return true
						default:
							return false
						}
					},
				}

				req := httptest.NewRequest("", "/", nil)
				err := s.refreshSession(nil, req, in.session)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(refreshed).To(Equal(in.expectRefreshed))
				Expect(saved).To(Equal(in.expectSaved))
			},
			Entry("when the provider refreshes the validSession", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
				},
				expectedErr:     nil,
				expectRefreshed: true,
				expectSaved:     true,
			}),
			Entry("when the provider returns an error", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: refreshError,
					CreatedAt:    &now,
					ExpiresOn:    &now,
				},
				expectedErr:     errors.New("error refreshing access token: error refreshing validSession"),
				expectRefreshed: false,
				expectSaved:     false,
			}),
			Entry("when saving the validSession returns an error", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					AccessToken:  "NoSave",
				},
				expectedErr:     errors.New("error saving validSession: unable to save validSession"),
				expectRefreshed: true,
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

		Context("with a valid validSession", func() {
			It("does not return an error", func() {
				expires := time.Now().Add(1 * time.Minute)
				session := &sessionsapi.SessionState{
					AccessToken: "Valid",
					ExpiresOn:   &expires,
				}
				Expect(s.validateSession(ctx, session)).To(Succeed())
			})
		})

		Context("with an expired validSession", func() {
			It("returns an error", func() {
				created := time.Now().Add(-5 * time.Minute)
				expires := time.Now().Add(-1 * time.Minute)
				session := &sessionsapi.SessionState{
					AccessToken: "Valid",
					CreatedAt:   &created,
					ExpiresOn:   &expires,
				}
				Expect(s.validateSession(ctx, session)).To(MatchError("validSession is expired"))
			})
		})

		Context("with an invalid validSession", func() {
			It("returns an error", func() {
				expires := time.Now().Add(1 * time.Minute)
				session := &sessionsapi.SessionState{
					AccessToken: "Invalid",
					ExpiresOn:   &expires,
				}
				Expect(s.validateSession(ctx, session)).To(MatchError("validSession is invalid"))
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

func (f *fakeSessionStore) LoadWithLock(req *http.Request) (*sessionsapi.SessionState, error) {
	return f.Load(req)
}

func (f *fakeSessionStore) ReleaseLock(req *http.Request) error {
	return nil
}

func (f *fakeSessionStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	if f.ClearFunc != nil {
		return f.ClearFunc(rw, req)
	}
	return nil
}
