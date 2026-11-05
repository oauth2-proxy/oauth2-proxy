package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/alicebob/miniredis/v2"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	redissessions "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/redis"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"
)

// rotatingProvider simulates a provider with single-use rotating refresh
// tokens (e.g. Kanidm): a refresh token is rotated as soon as the redeem
// request reaches the provider, and presenting a redeemed token again is
// detected as reuse and rejected.
type rotatingProvider struct {
	mu       sync.Mutex
	gen      int
	redeemed map[string]bool
	redeems  int
	reuses   int
	ctxErrs  []error

	// started receives the presented token when a redeem reaches the provider.
	started chan string
	// proceed, when non-nil, holds the response until it is closed or the
	// caller's context is done.
	proceed chan struct{}
}

func newRotatingProvider() *rotatingProvider {
	return &rotatingProvider{
		redeemed: map[string]bool{},
		started:  make(chan string, 16),
	}
}

func (p *rotatingProvider) refresh(ctx context.Context, ss *sessionsapi.SessionState) (bool, error) {
	presented := ss.RefreshToken

	p.mu.Lock()
	p.redeems++
	if p.redeemed[presented] {
		p.reuses++
		p.mu.Unlock()
		p.started <- presented
		return false, errors.New(`oauth2: "invalid_grant" "refresh token reuse detected"`)
	}
	p.redeemed[presented] = true
	p.gen++
	rotated := fmt.Sprintf("rt-%d", p.gen)
	p.mu.Unlock()

	p.started <- presented

	if p.proceed != nil {
		select {
		case <-p.proceed:
		case <-ctx.Done():
			// The provider already rotated the token, but the caller never
			// receives it.
			p.mu.Lock()
			p.ctxErrs = append(p.ctxErrs, ctx.Err())
			p.mu.Unlock()
			return false, ctx.Err()
		}
	}

	ss.RefreshToken = rotated
	ss.AccessToken = "at-" + rotated
	return true, nil
}

func (p *rotatingProvider) stats() (redeems, reuses int, ctxErrs []error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.redeems, p.reuses, append([]error(nil), p.ctxErrs...)
}

// memorySessionStore is a SessionStore that, like the persistent stores,
// fails when the request context is done and hands out a new lock instance on
// every load.
type memorySessionStore struct {
	mu      sync.Mutex
	stored  *sessionsapi.SessionState
	newLock func() sessionsapi.Lock
	// beforeLoad, when set, runs at the start of every Load.
	beforeLoad func()
	clears     int
}

func (m *memorySessionStore) Save(_ http.ResponseWriter, req *http.Request, s *sessionsapi.SessionState) error {
	if err := req.Context().Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	saved := *s
	saved.Lock = nil
	m.stored = &saved
	return nil
}

func (m *memorySessionStore) Load(req *http.Request) (*sessionsapi.SessionState, error) {
	if m.beforeLoad != nil {
		m.beforeLoad()
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stored == nil {
		return nil, nil
	}
	loaded := *m.stored
	loaded.Lock = m.newLock()
	return &loaded, nil
}

func (m *memorySessionStore) Clear(_ http.ResponseWriter, req *http.Request) error {
	if err := req.Context().Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stored = nil
	m.clears++
	return nil
}

func (m *memorySessionStore) clearCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clears
}

func (m *memorySessionStore) VerifyConnection(context.Context) error {
	return nil
}

func (m *memorySessionStore) refreshToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stored == nil {
		return ""
	}
	return m.stored.RefreshToken
}

// makeStale makes the stored session old enough to be refreshed again.
func (m *memorySessionStore) makeStale() {
	m.mu.Lock()
	defer m.mu.Unlock()
	past := time.Now().Add(-5 * time.Minute)
	m.stored.CreatedAt = &past
}

var _ = Describe("Stored session refresh with rotating refresh tokens", func() {
	const (
		ticketKey = "_oauth2_proxy-ticket"
		lockKey   = ticketKey + "." + redissessions.LockSuffix
		// The tests use a short refresh timeout and lock margin so that a
		// refresh that never completes is quick to run into its bound.
		refreshTimeout = 10 * time.Second
		lockMargin     = 300 * time.Millisecond
	)

	var (
		mr       *miniredis.Miniredis
		rdb      *redis.Client
		provider *rotatingProvider
		store    *memorySessionStore
		loader   *storedSessionLoader
	)

	newRedisLock := func() sessionsapi.Lock {
		return redissessions.NewLock(rdb, ticketKey)
	}

	BeforeEach(func() {
		var err error
		mr, err = miniredis.Run()
		Expect(err).ToNot(HaveOccurred())
		rdb = redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})

		provider = newRotatingProvider()
		store = &memorySessionStore{newLock: newRedisLock}
		past := time.Now().Add(-5 * time.Minute)
		store.stored = &sessionsapi.SessionState{
			Email:        "user@example.com",
			AccessToken:  "at-rt-0",
			RefreshToken: "rt-0",
			CreatedAt:    &past,
		}

		loader = &storedSessionLoader{
			store:               store,
			refreshPeriod:       time.Minute,
			sessionRefresher:    provider.refresh,
			sessionValidator:    func(context.Context, *sessionsapi.SessionState) bool { return true },
			refreshTimeout:      refreshTimeout,
			refreshLockDuration: lockMargin,
		}
	})

	AfterEach(func() {
		Expect(rdb.Close()).To(Succeed())
		mr.Close()
	})

	// refresh runs refreshSessionIfNeeded for a newly loaded session, like a
	// request carrying the session cookie.
	refresh := func(l *storedSessionLoader, ctx context.Context) (*sessionsapi.SessionState, error) {
		req := httptest.NewRequest("", "/", nil).WithContext(ctx)
		session, err := store.Load(req)
		Expect(err).ToNot(HaveOccurred())
		return session, l.refreshSessionIfNeeded(httptest.NewRecorder(), req, session)
	}

	type result struct {
		Session *sessionsapi.SessionState
		Err     error
	}

	refreshAsync := func(l *storedSessionLoader, ctx context.Context) <-chan result {
		done := make(chan result, 1)
		go func() {
			defer GinkgoRecover()
			session, err := refresh(l, ctx)
			done <- result{session, err}
		}()
		return done
	}

	// expectLockHeldThrough advances Redis time in steps up to total while a
	// refresh is in progress, and checks that nobody else can obtain the lock.
	expectLockHeldThrough := func(total time.Duration) {
		competitor := newRedisLock()
		const step = time.Second
		for elapsed := step; elapsed <= total; elapsed += step {
			mr.FastForward(step)
			Expect(competitor.Obtain(context.Background(), time.Second)).To(
				MatchError(sessionsapi.ErrLockNotObtained),
				"the refresh lock expired after %v of a refresh in progress", elapsed,
			)
		}
	}

	// pauseInLockReload blocks the reload a request does once it holds the
	// lock, until resume is closed. reloading is closed when it blocks.
	pauseInLockReload := func() (reloading, resume chan struct{}) {
		reloading, resume = make(chan struct{}), make(chan struct{})
		var mu sync.Mutex
		loads := 0
		store.beforeLoad = func() {
			mu.Lock()
			loads++
			n := loads
			mu.Unlock()
			if n == 2 {
				close(reloading)
				<-resume
			}
		}
		return reloading, resume
	}

	It("persists the rotated refresh token when the client cancels the request mid-refresh", func() {
		provider.proceed = make(chan struct{})
		reqCtx, cancelReq := context.WithCancel(context.Background())

		done := refreshAsync(loader, reqCtx)
		Eventually(provider.started).Should(Receive(Equal("rt-0")))

		// The client goes away while the provider is answering the redeem.
		cancelReq()
		close(provider.proceed)
		Eventually(done, 5*time.Second).Should(Receive())

		_, _, ctxErrs := provider.stats()
		Expect(ctxErrs).To(BeEmpty(), "the redeem was cancelled together with the client request")
		Expect(store.refreshToken()).To(Equal("rt-1"), "the rotated refresh token was not persisted")

		// The next refresh must present the rotated token, not the redeemed one.
		store.makeStale()
		session, err := refresh(loader, context.Background())
		Expect(err).ToNot(HaveOccurred())
		Eventually(provider.started).Should(Receive(Equal("rt-1")))
		Expect(session.RefreshToken).To(Equal("rt-2"))

		redeems, reuses, _ := provider.stats()
		Expect(reuses).To(BeZero())
		Expect(redeems).To(Equal(2))
	})

	It("holds the lock with the default timings for far longer than the previous 2 second lease", func() {
		defaults := *loader
		defaults.refreshTimeout, defaults.refreshLockDuration = 0, 0
		provider.proceed = make(chan struct{})

		done := refreshAsync(&defaults, context.Background())
		Eventually(provider.started).Should(Receive(Equal("rt-0")))

		Expect(mr.TTL(lockKey)).To(BeNumerically(">=", sessionRefreshTimeout),
			"the lock does not cover the refresh timeout")
		expectLockHeldThrough(sessionRefreshTimeout - time.Second)

		close(provider.proceed)
		Eventually(done, 5*time.Second).Should(Receive(HaveField("Err", BeNil())))
		Expect(store.refreshToken()).To(Equal("rt-1"))
		Expect(mr.Exists(lockKey)).To(BeFalse(), "the lock was not released")
	})

	It("redeems the refresh token once for concurrent requests during a long refresh", func() {
		const requests = 5
		provider.proceed = make(chan struct{})

		first := refreshAsync(loader, context.Background())
		Eventually(provider.started).Should(Receive(Equal("rt-0")))

		var others []<-chan result
		for i := 1; i < requests; i++ {
			others = append(others, refreshAsync(loader, context.Background()))
		}

		expectLockHeldThrough(5 * time.Second)
		Consistently(provider.started, 200*time.Millisecond).ShouldNot(Receive(), "a second redeem started while the first was in progress")

		close(provider.proceed)
		Eventually(first, 5*time.Second).Should(Receive(HaveField("Err", BeNil())))
		for _, done := range others {
			var r result
			Eventually(done, 5*time.Second).Should(Receive(&r))
			Expect(r.Err).ToNot(HaveOccurred())
			Expect(r.Session.RefreshToken).To(Equal("rt-1"), "a waiting request did not pick up the refreshed session")
		}

		redeems, reuses, _ := provider.stats()
		Expect(reuses).To(BeZero(), "a refresh token was redeemed more than once")
		Expect(redeems).To(Equal(1))
		Expect(store.refreshToken()).To(Equal("rt-1"))
	})

	It("keeps the lock while Redis is temporarily unavailable during the redeem", func() {
		provider.proceed = make(chan struct{})
		done := refreshAsync(loader, context.Background())
		Eventually(provider.started).Should(Receive(Equal("rt-0")))

		mr.SetError("LOADING Redis is loading the dataset in memory")
		mr.FastForward(5 * time.Second)
		mr.SetError("")

		// Once Redis is back, the lock is still held for the refresh.
		Expect(newRedisLock().Obtain(context.Background(), time.Second)).To(MatchError(sessionsapi.ErrLockNotObtained))

		close(provider.proceed)
		Eventually(done, 5*time.Second).Should(Receive(HaveField("Err", BeNil())))
		_, reuses, _ := provider.stats()
		Expect(reuses).To(BeZero())
		Expect(store.refreshToken()).To(Equal("rt-1"))
	})

	It("lets the lock expire on its own when it cannot be released", func() {
		provider.proceed = make(chan struct{})
		done := refreshAsync(loader, context.Background())
		Eventually(provider.started).Should(Receive(Equal("rt-0")))

		mr.SetError("LOADING Redis is loading the dataset in memory")
		close(provider.proceed)
		Eventually(done, 5*time.Second).Should(Receive(HaveField("Err", BeNil())))
		mr.SetError("")

		Expect(store.refreshToken()).To(Equal("rt-1"))
		Expect(newRedisLock().Obtain(context.Background(), time.Second)).To(MatchError(sessionsapi.ErrLockNotObtained))
		mr.FastForward(refreshTimeout + lockMargin)
		Expect(newRedisLock().Obtain(context.Background(), time.Second)).To(Succeed())
	})

	It("bounds a refresh that never completes and releases the lock", func() {
		provider.proceed = make(chan struct{}) // never closed
		loader.refreshTimeout = 200 * time.Millisecond

		done := refreshAsync(loader, context.Background())
		Eventually(provider.started).Should(Receive(Equal("rt-0")))

		// A non-fatal refresh error keeps the session and validates it.
		Eventually(done, 5*time.Second).Should(Receive(HaveField("Err", BeNil())))

		_, _, ctxErrs := provider.stats()
		Expect(ctxErrs).To(ConsistOf(MatchError(context.DeadlineExceeded)))
		Expect(store.refreshToken()).To(Equal("rt-0"), "nothing to persist after a timed out redeem")
		Expect(mr.Exists(lockKey)).To(BeFalse(), "the lock was not released after the timeout")
	})

	It("lets a waiting request refresh once the holder timed out before reaching the provider", func() {
		holderStuck := make(chan struct{})
		var calls sync.Mutex
		first := true
		loader.refreshTimeout = 300 * time.Millisecond
		loader.sessionRefresher = func(ctx context.Context, ss *sessionsapi.SessionState) (bool, error) {
			calls.Lock()
			isFirst := first
			first = false
			calls.Unlock()
			if isFirst {
				close(holderStuck)
				<-ctx.Done()
				return false, ctx.Err()
			}
			return provider.refresh(ctx, ss)
		}

		holder := refreshAsync(loader, context.Background())
		Eventually(holderStuck).Should(BeClosed())
		waiter := refreshAsync(loader, context.Background())

		Eventually(holder, 5*time.Second).Should(Receive(HaveField("Err", BeNil())))
		var r result
		Eventually(waiter, 5*time.Second).Should(Receive(&r))
		Expect(r.Err).ToNot(HaveOccurred())
		Expect(r.Session.RefreshToken).To(Equal("rt-1"))
		_, reuses, _ := provider.stats()
		Expect(reuses).To(BeZero())
	})

	It("lets a waiting request refresh once the lock of a holder that died expires", func() {
		dead := newRedisLock()
		Expect(dead.Obtain(context.Background(), refreshTimeout+lockMargin)).To(Succeed())

		waiter := refreshAsync(loader, context.Background())
		Consistently(provider.started, 50*time.Millisecond).ShouldNot(Receive())

		mr.FastForward(refreshTimeout + lockMargin)
		Eventually(provider.started, 5*time.Second).Should(Receive(Equal("rt-0")))
		var r result
		Eventually(waiter, 5*time.Second).Should(Receive(&r))
		Expect(r.Err).ToNot(HaveOccurred())
		Expect(r.Session.RefreshToken).To(Equal("rt-1"))
	})

	It("stops waiting for the lock when the waiting request is cancelled", func() {
		holder := newRedisLock()
		Expect(holder.Obtain(context.Background(), time.Minute)).To(Succeed())

		reqCtx, cancelReq := context.WithCancel(context.Background())
		done := refreshAsync(loader, reqCtx)
		Consistently(done, 50*time.Millisecond).ShouldNot(Receive())
		cancelReq()

		Eventually(done, 5*time.Second).Should(Receive(HaveField("Err", MatchError(ContainSubstring("stopped waiting for session lock")))))
		redeems, _, _ := provider.stats()
		Expect(redeems).To(BeZero())
		Expect(holder.Release(context.Background())).To(Succeed(), "the waiting request released a lock it did not hold")
	})

	Context("right before the redeem", func() {
		It("does not redeem when Redis is unavailable", func() {
			reloading, resume := pauseInLockReload()

			done := refreshAsync(loader, context.Background())
			Eventually(reloading).Should(BeClosed())

			// A rotated token could not be saved, and the lock not confirmed.
			mr.SetError("LOADING Redis is loading the dataset in memory")
			close(resume)
			Eventually(done, 5*time.Second).Should(Receive(HaveField("Err", BeNil())))
			mr.SetError("")

			redeems, _, _ := provider.stats()
			Expect(redeems).To(BeZero())
			Expect(store.refreshToken()).To(Equal("rt-0"))
			Expect(store.clearCount()).To(BeZero())
		})

		It("does not redeem when Redis lost the lock and another request obtained it", func() {
			reloading, resume := pauseInLockReload()

			done := refreshAsync(loader, context.Background())
			Eventually(reloading).Should(BeClosed())

			// E.g. a failover to a replica that did not have the lock yet.
			mr.Del(lockKey)
			competitor := newRedisLock()
			Expect(competitor.Obtain(context.Background(), time.Minute)).To(Succeed())

			close(resume)
			Eventually(done, 5*time.Second).Should(Receive(HaveField("Err", BeNil())))

			redeems, _, _ := provider.stats()
			Expect(redeems).To(BeZero(), "the refresh token was presented without holding the lock")
			Expect(competitor.Release(context.Background())).To(Succeed(), "the competitor's lock was touched")
		})

		It("does not take a lost lock back, because the reloaded session may be stale", func() {
			reloading, resume := pauseInLockReload()

			done := refreshAsync(loader, context.Background())
			Eventually(reloading).Should(BeClosed())

			mr.Del(lockKey)
			close(resume)
			Eventually(done, 5*time.Second).Should(Receive(HaveField("Err", BeNil())))

			redeems, _, _ := provider.stats()
			Expect(redeems).To(BeZero())
			Expect(mr.Exists(lockKey)).To(BeFalse())
		})
	})

	It("cannot prevent a second redeem when Redis loses the lock during the redeem (not covered by the lock)", func() {
		provider.proceed = make(chan struct{})
		holder := refreshAsync(loader, context.Background())
		Eventually(provider.started).Should(Receive(Equal("rt-0")))

		// E.g. a failover to a replica that did not have the lock yet.
		mr.Del(lockKey)
		_, err := refresh(loader, context.Background())
		Expect(err).To(MatchError(ContainSubstring("session invalidated due to fatal refresh error")))

		close(provider.proceed)
		Eventually(holder, 5*time.Second).Should(Receive())
		_, reuses, _ := provider.stats()
		Expect(reuses).To(Equal(1))
	})

	Context("when the lock cannot be obtained", func() {
		// serve runs a request through the stored session loader and returns
		// the session the next handler sees.
		serve := func(l *storedSessionLoader, ctx context.Context) *sessionsapi.SessionState {
			scope := &middlewareapi.RequestScope{}
			req := middlewareapi.AddRequestScope(httptest.NewRequest("", "/", nil).WithContext(ctx), scope)
			var seen *sessionsapi.SessionState
			handler := l.loadSession(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = middlewareapi.GetRequestScope(r).Session
			}))
			handler.ServeHTTP(httptest.NewRecorder(), req)
			return seen
		}

		It("keeps the session when it gives up waiting for another request's refresh", func() {
			provider.proceed = make(chan struct{})
			holder := refreshAsync(loader, context.Background())
			Eventually(provider.started).Should(Receive(Equal("rt-0")))

			// This request waits for the whole bound of the holder's refresh.
			waiter := *loader
			waiter.refreshTimeout = 100 * time.Millisecond
			session := serve(&waiter, context.Background())

			Expect(session).ToNot(BeNil(), "the request was served without its valid session")
			Expect(session.RefreshToken).To(Equal("rt-0"))
			Expect(store.clearCount()).To(BeZero(), "the session was cleared while another request was refreshing it")

			close(provider.proceed)
			Eventually(holder, 5*time.Second).Should(Receive(HaveField("Err", BeNil())))
			Expect(store.refreshToken()).To(Equal("rt-1"))
			redeems, _, _ := provider.stats()
			Expect(redeems).To(Equal(1))
		})

		It("keeps the session when Redis fails while obtaining the lock", func() {
			mr.SetError("LOADING Redis is loading the dataset in memory")

			session := serve(loader, context.Background())
			mr.SetError("")

			Expect(session).ToNot(BeNil())
			Expect(store.clearCount()).To(BeZero())
			redeems, _, _ := provider.stats()
			Expect(redeems).To(BeZero())
		})

		It("still clears a session that is no longer valid", func() {
			mr.SetError("LOADING Redis is loading the dataset in memory")
			loader.sessionValidator = func(context.Context, *sessionsapi.SessionState) bool { return false }

			session := serve(loader, context.Background())
			mr.SetError("")

			Expect(session).To(BeNil())
			Expect(store.clearCount()).To(Equal(1))
		})

		It("does not delete the session when the waiting request is cancelled", func() {
			holder := newRedisLock()
			Expect(holder.Obtain(context.Background(), time.Minute)).To(Succeed())

			reqCtx, cancelReq := context.WithCancel(context.Background())
			served := make(chan *sessionsapi.SessionState, 1)
			go func() {
				defer GinkgoRecover()
				served <- serve(loader, reqCtx)
			}()
			Consistently(served, 50*time.Millisecond).ShouldNot(Receive())
			cancelReq()

			Eventually(served, 5*time.Second).Should(Receive(BeNil()))
			Expect(store.clearCount()).To(BeZero())
			Expect(store.refreshToken()).To(Equal("rt-0"))
		})
	})

	Context("Redis lock ownership", func() {
		It("does not release, renew or extend a lock obtained by another request after it expired", func() {
			first := newRedisLock()
			Expect(first.Obtain(context.Background(), lockMargin)).To(Succeed())

			mr.FastForward(2 * lockMargin)

			second := newRedisLock()
			Expect(second.Obtain(context.Background(), time.Minute)).To(Succeed())

			Expect(first.Refresh(context.Background(), time.Hour)).To(MatchError(sessionsapi.ErrNotLocked))
			extendCtx, cancel := context.WithTimeout(context.Background(), time.Hour)
			defer cancel()
			Expect(extendLock(extendCtx, first, lockMargin)).To(MatchError(sessionsapi.ErrNotLocked))
			Expect(first.Release(context.Background())).To(MatchError(sessionsapi.ErrNotLocked))

			Expect(mr.TTL(lockKey)).To(BeNumerically("<=", time.Minute), "the other request's lock was extended")
			locked, err := second.Peek(context.Background())
			Expect(err).ToNot(HaveOccurred())
			Expect(locked).To(BeTrue())
			Expect(second.Release(context.Background())).To(Succeed())
		})

		It("extends a held lock to the refresh deadline", func() {
			lock := newRedisLock()
			Expect(lock.Obtain(context.Background(), lockMargin)).To(Succeed())

			extendCtx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
			defer cancel()
			Expect(extendLock(extendCtx, lock, lockMargin)).To(Succeed())

			Expect(mr.TTL(lockKey)).To(BeNumerically(">", refreshTimeout-time.Second))
			Expect(mr.TTL(lockKey)).To(BeNumerically("<=", refreshTimeout+lockMargin))
			Expect(lock.Release(context.Background())).To(Succeed())
		})
	})
})
