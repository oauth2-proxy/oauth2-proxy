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
type tenantIDValidator struct {
	sessions.SessionStore
}

func (tiv *tenantIDValidator) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	s.TenantID = tenantutils.FromContext(req.Context())

	return tiv.SessionStore.Save(rw, req, s)
}

func (tiv *tenantIDValidator) Load(req *http.Request) (*sessions.SessionState, error) {
	s, err := tiv.SessionStore.Load(req)
	if err != nil {
		return s, err
	}

	reqTenantID := tenantutils.FromContext(req.Context())
	sessionsTenantID := s.TenantID
	if reqTenantID == sessionsTenantID {
		return s, nil
	}
	logger.Error(fmt.Sprintf("tenantId conflict in incoming request '%s' and cookie '%s'", reqTenantID, sessionsTenantID))
	return nil, fmt.Errorf("tenantid conflict in request and cookie")
}

func TenantIDValidator(s sessions.SessionStore) sessions.SessionStore {
	return &tenantIDValidator{
		SessionStore: s,
	}
}
