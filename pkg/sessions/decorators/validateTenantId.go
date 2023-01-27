package decorators

import (
	"fmt"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	tenantutils "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/tenant/utils"
)

// this is a decorator/wrapper over SessionStore
// it validates that the tenantId in the incoming request and in the SessionState should be same
type tenantIdValidator struct {
	sessions.SessionStore
}

func (tiv *tenantIdValidator) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	s.TenantId = tenantutils.FromContext(req.Context())

	return tiv.SessionStore.Save(rw, req, s)
}

func (tiv *tenantIdValidator) Load(req *http.Request) (*sessions.SessionState, error) {
	s, err := tiv.SessionStore.Load(req)
	if err != nil {
		return s, err
	}

	reqTenantId := tenantutils.FromContext(req.Context())
	sessionsTenantId := s.TenantId
	if reqTenantId == sessionsTenantId {
		return s, nil
	} else {
		logger.Error(fmt.Sprintf("tenantId conflict in incoming request '%s' and cookie '%s'", reqTenantId, sessionsTenantId))
		return nil, fmt.Errorf("tenantid conflict in request and cookie")
	}
}

func TenantIdValidator(s sessions.SessionStore) sessions.SessionStore {
	return &tenantIdValidator{
		SessionStore: s,
	}
}
