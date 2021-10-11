package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/clock"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

type TestLock struct {
	Locked       bool
	WasObtained  bool
	WasRefreshed bool
	WasReleased  bool
	PeekedCount  int
	ObtainError  error
	PeekError    error
	RefreshError error
	ReleaseError error
}

func (l *TestLock) Obtain(_ context.Context, _ time.Duration) error {
	if l.ObtainError != nil {
		return l.ObtainError
	}
	l.Locked = true
	l.WasObtained = true
	return nil
}

func (l *TestLock) Peek(_ context.Context) (bool, error) {
	if l.PeekError != nil {
		return false, l.PeekError
	}
	locked := l.Locked
	l.Locked = false
	l.PeekedCount++
	return locked, nil
}

func (l *TestLock) Refresh(_ context.Context, _ time.Duration) error {
	if l.RefreshError != nil {
		return l.ReleaseError
	}
	l.WasRefreshed = true
	return nil
}

func (l *TestLock) Release(_ context.Context) error {
	if l.ReleaseError != nil {
		return l.ReleaseError
	}
	l.Locked = false
	l.WasReleased = true
	return nil
}

type LockConc struct {
	mu          sync.Mutex
	lock        bool
	disablePeek bool
}

func (l *LockConc) Obtain(_ context.Context, _ time.Duration) error {
	l.mu.Lock()
	if l.lock {
		l.mu.Unlock()
		return sessionsapi.ErrLockNotObtained
	}
	l.lock = true
	l.mu.Unlock()
	return nil
}

func (l *LockConc) Peek(_ context.Context) (bool, error) {
	var response bool
	l.mu.Lock()
	if l.disablePeek {
		response = false
	} else {
		response = l.lock
	}
	l.mu.Unlock()
	return response, nil
}

func (l *LockConc) Refresh(_ context.Context, _ time.Duration) error {
	return nil
}

func (l *LockConc) Release(_ context.Context) error {
	l.mu.Lock()
	l.lock = false
	l.mu.Unlock()
	return nil
}

var _ = Describe("Stored Session Suite", func() {
	const (
		refresh        = "Refresh"
		refreshed      = "Refreshed"
		noRefresh      = "NoRefresh"
		notImplemented = "NotImplemented"
	)

	var ctx = context.Background()

	Context("StoredSessionLoader", func() {
		now := time.Now()
		createdPast := now.Add(-5 * time.Minute)
		createdFuture := now.Add(5 * time.Minute)

		var defaultRefreshFunc = func(_ context.Context, ss *sessionsapi.SessionState) (bool, error) {
			switch ss.RefreshToken {
			case refresh:
				ss.RefreshToken = refreshed
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

		BeforeEach(func() {
			clock.Set(now)
		})

		AfterEach(func() {
			clock.Reset()
		})

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

				// Set up the request with the request header and a request scope
				req := httptest.NewRequest("", "/", nil)
				req.Header = in.requestHeaders
				req = middlewareapi.AddRequestScope(req, scope)

				rw := httptest.NewRecorder()

				opts := &StoredSessionLoaderOptions{
					SessionStore:    in.store,
					RefreshPeriod:   in.refreshPeriod,
					RefreshSession:  in.refreshSession,
					ValidateSession: in.validateSession,
				}

				// Create the handler with a next handler that will capture the session
				// from the scope
				var gotSession *sessionsapi.SessionState
				handler := NewStoredSessionLoader(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gotSession = middlewareapi.GetRequestScope(r).Session
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
					Lock:         &sessionsapi.NoOpLock{},
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
					CreatedAt:    &now,
					ExpiresOn:    &createdFuture,
					Lock:         &sessionsapi.NoOpLock{},
				},
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("when the provider refresh fails but validation succeeds", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=RefreshError"},
				},
				existingSession: nil,
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: "RefreshError",
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
					Lock:         &sessionsapi.NoOpLock{},
				},
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("when the provider refresh fails and validation fails", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=RefreshError"},
				},
				existingSession: nil,
				expectedSession: nil,
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: func(context.Context, *sessionsapi.SessionState) bool { return false },
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

		type storedSessionLoaderConcurrentTableInput struct {
			existingSession *sessionsapi.SessionState
			refreshPeriod   time.Duration
			numConcReqs     int
		}

		DescribeTable("when serving concurrent requests",
			func(in storedSessionLoaderConcurrentTableInput) {
				lockConc := &LockConc{}

				refreshedChan := make(chan bool, in.numConcReqs)
				for i := 0; i < in.numConcReqs; i++ {
					go func(refreshedChan chan bool, lockConc sessionsapi.Lock) {
						existingSession := *in.existingSession // deep copy existingSession state
						existingSession.Lock = lockConc
						store := &fakeSessionStore{
							LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
								return &existingSession, nil
							},
							SaveFunc: func(http.ResponseWriter, *http.Request, *sessionsapi.SessionState) error {
								return nil
							},
						}

						scope := &middlewareapi.RequestScope{
							Session: nil,
						}

						// Set up the request with the request header and a request scope
						req := httptest.NewRequest("", "/", nil)
						req = middlewareapi.AddRequestScope(req, scope)

						rw := httptest.NewRecorder()

						sessionRefreshed := false
						opts := &StoredSessionLoaderOptions{
							SessionStore:  store,
							RefreshPeriod: in.refreshPeriod,
							RefreshSession: func(ctx context.Context, s *sessionsapi.SessionState) (bool, error) {
								time.Sleep(10 * time.Millisecond)
								sessionRefreshed = true
								return true, nil
							},
							ValidateSession: func(context.Context, *sessionsapi.SessionState) bool {
								return true
							},
						}

						handler := NewStoredSessionLoader(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
						handler.ServeHTTP(rw, req)

						refreshedChan <- sessionRefreshed
					}(refreshedChan, lockConc)
				}
				var refreshedSlice []bool
				for i := 0; i < in.numConcReqs; i++ {
					refreshedSlice = append(refreshedSlice, <-refreshedChan)
				}
				sessionRefreshedCount := 0
				for _, sessionRefreshed := range refreshedSlice {
					if sessionRefreshed {
						sessionRefreshedCount++
					}
				}
				Expect(sessionRefreshedCount).To(Equal(1))
			},
			Entry("with two concurrent requests", storedSessionLoaderConcurrentTableInput{
				existingSession: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
				},
				numConcReqs:   2,
				refreshPeriod: 1 * time.Minute,
			}),
			Entry("with 5 concurrent requests", storedSessionLoaderConcurrentTableInput{
				existingSession: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
				},
				numConcReqs:   5,
				refreshPeriod: 1 * time.Minute,
			}),
			Entry("with one request", storedSessionLoaderConcurrentTableInput{
				existingSession: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
				},
				numConcReqs:   1,
				refreshPeriod: 1 * time.Minute,
			}),
		)
	})

	Context("refreshSessionIfNeeded", func() {
		type refreshSessionIfNeededTableInput struct {
			refreshPeriod     time.Duration
			sessionStored     bool
			session           *sessionsapi.SessionState
			expectedErr       error
			expectRefreshed   bool
			expectedLockState TestLock
		}

		createdPast := time.Now().Add(-5 * time.Minute)
		createdFuture := time.Now().Add(5 * time.Minute)

		DescribeTable("with a session",
			func(in refreshSessionIfNeededTableInput) {
				refreshed := false

				store := &fakeSessionStore{}
				if in.sessionStored {
					store = &fakeSessionStore{
						LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
							return in.session, nil
						},
					}
				}

				s := &storedSessionLoader{
					refreshPeriod: in.refreshPeriod,
					store:         store,
					sessionRefresher: func(_ context.Context, ss *sessionsapi.SessionState) (bool, error) {
						refreshed = true
						switch ss.RefreshToken {
						case refresh:
							return true, nil
						case noRefresh:
							return false, nil
						case notImplemented:
							return false, providers.ErrNotImplemented
						default:
							return false, errors.New("error refreshing session")
						}
					},
					sessionValidator: func(_ context.Context, ss *sessionsapi.SessionState) bool {
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
				testLock, ok := in.session.Lock.(*TestLock)
				Expect(ok).To(Equal(true))

				Expect(testLock).To(Equal(&in.expectedLockState))
			},
			Entry("when the refresh period is 0, and the session does not need refreshing", refreshSessionIfNeededTableInput{
				refreshPeriod: time.Duration(0),
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdFuture,
					Lock:         &TestLock{},
				},
				expectedErr:       nil,
				expectRefreshed:   false,
				expectedLockState: TestLock{},
			}),
			Entry("when the refresh period is 0, and the session needs refreshing", refreshSessionIfNeededTableInput{
				refreshPeriod: time.Duration(0),
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
					Lock:         &TestLock{},
				},
				expectedErr:       nil,
				expectRefreshed:   false,
				expectedLockState: TestLock{},
			}),
			Entry("when the session does not need refreshing", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdFuture,
					Lock:         &TestLock{},
				},
				expectedErr:       nil,
				expectRefreshed:   false,
				expectedLockState: TestLock{},
			}),
			Entry("when the session is refreshed by the provider", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
					Lock:         &TestLock{},
				},
				expectedErr:     nil,
				expectRefreshed: true,
				expectedLockState: TestLock{
					Locked:      false,
					WasObtained: true,
					WasReleased: true,
					PeekedCount: 1,
				},
			}),
			Entry("when the session is locked and instead loaded from storage", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					Lock: &TestLock{
						Locked: true,
					},
				},
				sessionStored:   true,
				expectedErr:     nil,
				expectRefreshed: false,
				expectedLockState: TestLock{
					Locked:      false,
					PeekedCount: 2,
				},
			}),
			Entry("when obtaining lock failed", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					Lock: &TestLock{
						ObtainError: errors.New("not able to obtain lock"),
					},
				},
				expectedErr:     nil,
				expectRefreshed: false,
				expectedLockState: TestLock{
					PeekedCount: 1,
					ObtainError: errors.New("not able to obtain lock"),
				},
			}),
			Entry("when the session is not refreshed by the provider", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
					Lock:         &TestLock{},
				},
				expectedErr:     nil,
				expectRefreshed: true,
				expectedLockState: TestLock{
					Locked:      false,
					WasObtained: true,
					WasReleased: true,
					PeekedCount: 1,
				},
			}),
			Entry("when the provider doesn't implement refresh", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: notImplemented,
					CreatedAt:    &createdPast,
					Lock:         &TestLock{},
				},
				expectedErr:     nil,
				expectRefreshed: true,
				expectedLockState: TestLock{
					Locked:      false,
					WasObtained: true,
					WasReleased: true,
					PeekedCount: 1,
				},
			}),
			Entry("when the session is not refreshed by the provider", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					AccessToken:  "Invalid",
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
					Lock:         &TestLock{},
				},
				expectedErr:     nil,
				expectRefreshed: true,
				expectedLockState: TestLock{
					Locked:      false,
					WasObtained: true,
					WasReleased: true,
					PeekedCount: 1,
				},
			}),
		)
	})

	Context("refreshSession", func() {
		type refreshSessionWithProviderTableInput struct {
			session     *sessionsapi.SessionState
			expectedErr error
			expectSaved bool
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
					sessionRefresher: func(_ context.Context, ss *sessionsapi.SessionState) (bool, error) {
						switch ss.RefreshToken {
						case refresh:
							return true, nil
						case noRefresh:
							return false, nil
						case notImplemented:
							return false, providers.ErrNotImplemented
						default:
							return false, errors.New("error refreshing session")
						}
					},
				}

				req := httptest.NewRequest("", "/", nil)
				req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})
				err := s.refreshSession(nil, req, in.session)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(saved).To(Equal(in.expectSaved))
			},
			Entry("when the provider does not refresh the session", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
				},
				expectedErr: nil,
				expectSaved: false,
			}),
			Entry("when the provider refreshes the session", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
				},
				expectedErr: nil,
				expectSaved: true,
			}),
			Entry("when the provider doesn't implement refresh", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: notImplemented,
				},
				expectedErr: nil,
				expectSaved: true,
			}),
			Entry("when the provider returns an error", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: "RefreshError",
					CreatedAt:    &now,
					ExpiresOn:    &now,
				},
				expectedErr: errors.New("error refreshing tokens: error refreshing session"),
				expectSaved: false,
			}),
			Entry("when the saving the session returns an error", refreshSessionWithProviderTableInput{
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					AccessToken:  "NoSave",
				},
				expectedErr: errors.New("error saving session: unable to save session"),
				expectSaved: true,
			}),
		)
	})

	Context("validateSession", func() {
		var s *storedSessionLoader

		BeforeEach(func() {
			s = &storedSessionLoader{
				sessionValidator: func(_ context.Context, ss *sessionsapi.SessionState) bool {
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
