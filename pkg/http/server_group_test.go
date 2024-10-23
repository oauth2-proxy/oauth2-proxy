package http

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Server Group", func() {
	var m1, m2, m3 *mockServer
	var ctx context.Context
	var cancel context.CancelFunc
	var group Server

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())

		m1 = newMockServer()
		m2 = newMockServer()
		m3 = newMockServer()
		group = NewServerGroup(m1, m2, m3)
	})

	AfterEach(func() {
		cancel()
	})

	It("starts each server in the group", func() {
		go func() {
			defer GinkgoRecover()
			Expect(group.Start(ctx)).To(Succeed())
		}()

		Eventually(m1.started).Should(BeClosed(), "mock server 1 not started")
		Eventually(m2.started).Should(BeClosed(), "mock server 2 not started")
		Eventually(m3.started).Should(BeClosed(), "mock server 3 not started")
	})

	It("stop each server in the group when the context is cancelled", func() {
		go func() {
			defer GinkgoRecover()
			Expect(group.Start(ctx)).To(Succeed())
		}()

		cancel()
		Eventually(m1.stopped).Should(BeClosed(), "mock server 1 not stopped")
		Eventually(m2.stopped).Should(BeClosed(), "mock server 2 not stopped")
		Eventually(m3.stopped).Should(BeClosed(), "mock server 3 not stopped")
	})

	It("stop each server in the group when the an error occurs", func() {
		err := errors.New("server error")
		go func() {
			defer GinkgoRecover()
			Expect(group.Start(ctx)).To(MatchError(err))
		}()

		m2.errors <- err
		Eventually(m1.stopped).Should(BeClosed(), "mock server 1 not stopped")
		Eventually(m2.stopped).Should(BeClosed(), "mock server 2 not stopped")
		Eventually(m3.stopped).Should(BeClosed(), "mock server 3 not stopped")
	})
})

// mockServer is used to test the server group can start
// and stop multiple servers simultaneously.
type mockServer struct {
	started     chan struct{}
	startClosed bool
	stopped     chan struct{}
	stopClosed  bool
	errors      chan error
}

func newMockServer() *mockServer {
	return &mockServer{
		started: make(chan struct{}),
		stopped: make(chan struct{}),
		errors:  make(chan error),
	}
}

func (m *mockServer) Start(ctx context.Context) error {
	if !m.startClosed {
		close(m.started)
		m.startClosed = true
	}
	defer func() {
		if !m.stopClosed {
			close(m.stopped)
			m.stopClosed = true
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-m.errors:
		return err
	}
}
