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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type testLock struct {
	locked          bool
	obtainOnAttempt int
	obtainAttempts  int
	obtainError     error
}

func (l *testLock) Obtain(_ context.Context, _ time.Duration) error {
	l.obtainAttempts++
	if l.obtainAttempts < l.obtainOnAttempt {
		return sessionsapi.ErrLockNotObtained
	}
	if l.obtainError != nil {
		return l.obtainError
	}
	l.locked = true
	return nil
}

func (l *testLock) Peek(_ context.Context) (bool, error) {
	return l.locked, nil
}

func (l *testLock) Refresh(_ context.Context, _ time.Duration) error {
	return nil
}

func (l *testLock) Release(_ context.Context) error {
	l.locked = false
	return nil
}

type testLockConcurrent struct {
	mu     sync.RWMutex
	locked bool
}

func (l *testLockConcurrent) Obtain(_ context.Context, _ time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.locked {
		return sessionsapi.ErrLockNotObtained
	}
	l.locked = true
	return nil
}

func (l *testLockConcurrent) Peek(_ context.Context) (bool, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.locked, nil
}

func (l *testLockConcurrent) Refresh(_ context.Context, _ time.Duration) error {
	return nil
}

func (l *testLockConcurrent) Release(_ context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.locked = false
	return nil
}

var _ = Describe("Stored Session Suite", func() {
	const (
		refresh        = "Refresh"
		refreshed      = "Refreshed"
		forcedRefresh  = "Forced-Refresh"
		noRefresh      = "NoRefresh"
		notImplemented = "NotImplemented"
	)

	var ctx = context.Background()

	Context("StoredSessionLoader", func() {
		now := time.Now()
		createdPast := now.Add(-5 * time.Minute)
		recentPast := now.Add(-5 * time.Second)
		createdFuture := now.Add(5 * time.Minute)
		recent := now.Add(1 * time.Minute)

		var defaultRefreshFunc = func(_ context.Context, ss *sessionsapi.SessionState) (bool, error) {
			switch ss.RefreshToken {
			case refresh:
				ss.RefreshToken = refreshed
				return true, nil
			case forcedRefresh:
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
				case "_oauth2_proxy=NewSession":
					return &sessionsapi.SessionState{
						RefreshToken: "Forced-Refresh", // used to inform test to allow refresh.  Will be overwritten
						CreatedAt:    &recentPast,
						ExpiresOn:    &createdFuture,
					}, nil
				case "_oauth2_proxy=OldSession":
					return &sessionsapi.SessionState{
						RefreshToken: "Forced-Refresh", // used to inform test to allow refresh.  Will be overwritten
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
			clock.Set(recent)
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

		DescribeTable("when serving a loadSession request",
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
					CreatedAt:    &recent,
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

		DescribeTable("when service a forceRefresh request",
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
				handler := NewStoredSessionRefresher(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
					"Cookie": []string{"_oauth2_proxy=NewSession"},
				},
				existingSession: &sessionsapi.SessionState{
					RefreshToken: "Forced-Refresh",
					CreatedAt:    &recentPast,
				},
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: "Refreshed",
					CreatedAt:    &recent,
					ExpiresOn:    &createdFuture,
					Lock:         &sessionsapi.NoOpLock{},
				},
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("with a session that has not expired and cannot be refreshed", storedSessionLoaderTableInput{
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
					"Cookie": []string{"_oauth2_proxy=NewSession"},
				},
				existingSession: nil,
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: "Refreshed",
					CreatedAt:    &recent,
					ExpiresOn:    &createdFuture,
					Lock:         &sessionsapi.NoOpLock{},
				},
				store:           defaultSessionStore,
				refreshPeriod:   1 * time.Minute,
				refreshSession:  defaultRefreshFunc,
				validateSession: defaultValidateFunc,
			}),
			Entry("with a session that can refresh and is older than the refresh period", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=OldSession"},
				},
				existingSession: nil,
				expectedSession: &sessionsapi.SessionState{
					RefreshToken: "Refreshed",
					CreatedAt:    &recent,
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
			Entry("when refresh period is not defined", storedSessionLoaderTableInput{
				requestHeaders: http.Header{
					"Cookie": []string{"_oauth2_proxy=NewSession"},
				},
				existingSession: nil,
				expectedSession: nil,
				store:           defaultSessionStore,
				refreshPeriod:   0,
			}),
		)

		type storedSessionLoaderConcurrentTableInput struct {
			existingSession *sessionsapi.SessionState
			refreshPeriod   time.Duration
			numConcReqs     int
		}

		DescribeTable("when serving concurrent requests",
			func(in storedSessionLoaderConcurrentTableInput) {
				lockConc := &testLockConcurrent{}

				lock := &sync.RWMutex{}
				existingSession := *in.existingSession // deep copy existingSession state
				existingSession.Lock = lockConc
				store := &fakeSessionStore{
					LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
						lock.RLock()
						defer lock.RUnlock()
						session := existingSession
						return &session, nil
					},
					SaveFunc: func(_ http.ResponseWriter, _ *http.Request, session *sessionsapi.SessionState) error {
						lock.Lock()
						defer lock.Unlock()
						existingSession = *session
						return nil
					},
				}

				refreshedChan := make(chan bool, in.numConcReqs)
				for i := 0; i < in.numConcReqs; i++ {
					go func(refreshedChan chan bool, lockConc sessionsapi.Lock) {
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
			refreshPeriod            time.Duration
			session                  *sessionsapi.SessionState
			concurrentSessionRefresh bool
			expectedErr              error
			expectRefreshed          bool
			expectValidated          bool
			expectedLockObtained     bool
		}

		createdPast := time.Now().Add(-5 * time.Minute)
		createdFuture := time.Now().Add(5 * time.Minute)

		DescribeTable("with a session",
			func(in refreshSessionIfNeededTableInput) {
				refreshed := false
				validated := false

				session := &sessionsapi.SessionState{}
				*session = *in.session
				if in.concurrentSessionRefresh {
					// Update the session that Load returns.
					// This simulates a concurrent refresh in the background.
					session.CreatedAt = &createdFuture
				}
				store := &fakeSessionStore{
					LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
						// Loading the session from the provider creates a new lock
						session.Lock = &testLock{}
						return session, nil
					},
					SaveFunc: func(_ http.ResponseWriter, _ *http.Request, s *sessionsapi.SessionState) error {
						*session = *s
						return nil
					},
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
						validated = true
						return ss.AccessToken != "Invalid"
					},
				}

				req := httptest.NewRequest("", "/", nil)
				err := s.refreshSessionIfNeeded(nil, req, in.session, false)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(refreshed).To(Equal(in.expectRefreshed))
				Expect(validated).To(Equal(in.expectValidated))
				testLock, ok := in.session.Lock.(*testLock)
				Expect(ok).To(Equal(true))

				if in.expectedLockObtained {
					Expect(testLock.obtainAttempts).Should(BeNumerically(">", 0), "Expected at least one attempt at obtaining the session lock")
				}
				Expect(testLock.locked).To(BeFalse(), "Expected lock should always be released")
			},
			Entry("when the refresh period is 0, and the session does not need refreshing", refreshSessionIfNeededTableInput{
				refreshPeriod: time.Duration(0),
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdFuture,
					Lock:         &testLock{},
				},
				expectedErr:          nil,
				expectRefreshed:      false,
				expectValidated:      false,
				expectedLockObtained: false,
			}),
			Entry("when the refresh period is 0, and the session needs refreshing", refreshSessionIfNeededTableInput{
				refreshPeriod: time.Duration(0),
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
					Lock:         &testLock{},
				},
				expectedErr:          nil,
				expectRefreshed:      false,
				expectValidated:      false,
				expectedLockObtained: false,
			}),
			Entry("when the session does not need refreshing", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdFuture,
					Lock:         &testLock{},
				},
				expectedErr:          nil,
				expectRefreshed:      false,
				expectValidated:      false,
				expectedLockObtained: false,
			}),
			Entry("when the session is refreshed by the provider", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: refresh,
					CreatedAt:    &createdPast,
					Lock:         &testLock{},
				},
				expectedErr:          nil,
				expectRefreshed:      true,
				expectValidated:      true,
				expectedLockObtained: true,
			}),
			Entry("when obtaining lock failed, but concurrent request refreshed", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					Lock: &testLock{
						obtainOnAttempt: 4,
					},
				},
				concurrentSessionRefresh: true,
				expectedErr:              nil,
				expectRefreshed:          false,
				expectValidated:          false,
				expectedLockObtained:     true,
			}),
			Entry("when obtaining lock failed with a valid session", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					Lock: &testLock{
						obtainError: sessionsapi.ErrLockNotObtained,
					},
				},
				expectedErr:          errors.New("timeout obtaining session lock"),
				expectRefreshed:      false,
				expectValidated:      false,
				expectedLockObtained: true,
			}),
			Entry("when the session is not refreshed by the provider", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
					Lock:         &testLock{},
				},
				expectedErr:          nil,
				expectRefreshed:      true,
				expectValidated:      true,
				expectedLockObtained: true,
			}),
			Entry("when the provider doesn't implement refresh", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					RefreshToken: notImplemented,
					CreatedAt:    &createdPast,
					Lock:         &testLock{},
				},
				expectedErr:          nil,
				expectRefreshed:      true,
				expectValidated:      true,
				expectedLockObtained: true,
			}),
			Entry("when the session is not refreshed by the provider", refreshSessionIfNeededTableInput{
				refreshPeriod: 1 * time.Minute,
				session: &sessionsapi.SessionState{
					AccessToken:  "Invalid",
					RefreshToken: noRefresh,
					CreatedAt:    &createdPast,
					ExpiresOn:    &createdFuture,
					Lock:         &testLock{},
				},
				expectedErr:          errors.New("session is invalid"),
				expectRefreshed:      true,
				expectValidated:      true,
				expectedLockObtained: true,
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

func (f *fakeSessionStore) VerifyConnection(_ context.Context) error {
	return nil
}
