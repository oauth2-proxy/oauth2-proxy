package middleware

import (
	"fmt"
	"net"
	"net/http"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/pagewriter"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/authorization"
)

func NewRequestAuthorization(writer pagewriter.Writer, requestRules []options.AuthorizationRule, getClientIPFunc func(*http.Request) net.IP) (alice.Constructor, error) {
	ruleset, err := authorization.NewRuleSet(requestRules, getClientIPFunc)
	if err != nil {
		return nil, fmt.Errorf("could not initialise ruleset: %w", err)
	}

	ra := &requestAuthorizer{
		ruleset: ruleset,
		writer:  writer,
	}

	return ra.checkRequestAuthorization, nil
}

type requestAuthorizer struct {
	ruleset authorization.RuleSet
	writer  pagewriter.Writer
}

func (r *requestAuthorizer) checkRequestAuthorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Authorization.Policy != middlewareapi.OmittedPolicy {
			// The request was already authorized, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		policy := r.ruleset.MatchesRequest(req)
		switch policy {
		case middlewareapi.AllowPolicy, middlewareapi.DelegatePolicy:
			scope.Authorization.Type = middlewareapi.RequestAuthorization
			scope.Authorization.Policy = policy
		case middlewareapi.DenyPolicy:
			r.writer.WriteErrorPage(rw, pagewriter.ErrorPageOpts{
				Status:    http.StatusForbidden,
				RequestID: scope.RequestID,
				AppError:  "Request denied by authorization policy",
				Messages:  []interface{}{"Request denied by authorization policy"},
			})
		}

		next.ServeHTTP(rw, req)
	})
}
