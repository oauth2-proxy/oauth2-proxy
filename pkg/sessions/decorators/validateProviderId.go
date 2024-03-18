package decorators

import (
	"fmt"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/utils"
)

// this is a decorator/wrapper over SessionStore
// it validates that the providerId in the incoming request and in the SessionState should be same
type providerIDValidator struct {
	sessions.SessionStore
}

func (tiv *providerIDValidator) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	s.ProviderID = utils.FromContext(req.Context())

	return tiv.SessionStore.Save(rw, req, s)
}

func (tiv *providerIDValidator) Load(req *http.Request) (*sessions.SessionState, error) {
	s, err := tiv.SessionStore.Load(req)
	if err != nil {
		return s, err
	}

	reqProviderID := utils.FromContext(req.Context())
	sessionsProviderID := s.ProviderID
	if reqProviderID == sessionsProviderID {
		return s, nil
	}
	logger.Error(fmt.Sprintf("providerId conflict in incoming request '%s' and cookie '%s'", reqProviderID, sessionsProviderID))
	return nil, fmt.Errorf("providerid conflict in request and cookie")
}

func ProviderIDValidator(s sessions.SessionStore) sessions.SessionStore {
	return &providerIDValidator{
		SessionStore: s,
	}
}
