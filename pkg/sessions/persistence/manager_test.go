package persistence

import (
	"errors"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"
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

type closeableStore struct {
	Store
	err error
}

func (s *closeableStore) Close() error { return s.err }

func TestManagerClose(t *testing.T) {
	require.NoError(t, NewManager(tests.NewMockStore(), nil).Close())
	err := errors.New("close failed")
	require.ErrorIs(t, NewManager(&closeableStore{err: err}, nil).Close(), err)
}
