package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	k8serrors "k8s.io/apimachinery/pkg/util/errors"
)

const jwtRegexFormat = `^ey[IJ][a-zA-Z0-9_-]*\.ey[IJ][a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+$`

func NewJwtSessionLoader(sessionLoaders []middlewareapi.TokenToSessionFunc) alice.Constructor {
	js := &jwtSessionLoader{
		jwtRegex:       regexp.MustCompile(jwtRegexFormat),
		sessionLoaders: sessionLoaders,
	}
	return js.loadSession
}

// jwtSessionLoader is responsible for loading sessions from JWTs in
// Authorization headers.
type jwtSessionLoader struct {
	jwtRegex       *regexp.Regexp
	sessionLoaders []middlewareapi.TokenToSessionFunc
}

// loadSession attempts to load a session from a JWT stored in an Authorization
// header within the request.
// If no authorization header is found, or the header is invalid, no session
// will be loaded and the request will be passed to the next handler.
// If a session was loaded by a previous handler, it will not be replaced.
func (j *jwtSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		session, err := j.getJwtSession(req)
		if err != nil {
			logger.Errorf("Error retrieving session from token in Authorization header: %v", err)
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getJwtSession loads a session based on a JWT token in the authorization header.
// (see the config options skip-jwt-bearer-tokens and extra-jwt-issuers)
func (j *jwtSessionLoader) getJwtSession(req *http.Request) (*sessionsapi.SessionState, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		// No auth header provided, so don't attempt to load a session
		return nil, nil
	}

	token, err := j.findTokenFromHeader(auth)
	if err != nil {
		return nil, err
	}

	// This leading error message only occurs if all session loaders fail
	errs := []error{errors.New("unable to verify bearer token")}
	for _, loader := range j.sessionLoaders {
		session, err := loader(req.Context(), token)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return session, nil
	}

	return nil, k8serrors.NewAggregate(errs)
}

// findTokenFromHeader finds a valid JWT token from the Authorization header of a given request.
func (j *jwtSessionLoader) findTokenFromHeader(header string) (string, error) {
	tokenType, token, err := splitAuthHeader(header)
	if err != nil {
		return "", err
	}

	if tokenType == "Bearer" && j.jwtRegex.MatchString(token) {
		// Found a JWT as a bearer token
		return token, nil
	}

	if tokenType == "Basic" {
		// Check if we have a Bearer token masquerading in Basic
		return j.getBasicToken(token)
	}

	return "", fmt.Errorf("no valid bearer token found in authorization header")
}

// getBasicToken tries to extract a token from the basic value provided.
func (j *jwtSessionLoader) getBasicToken(token string) (string, error) {
	user, password, err := getBasicAuthCredentials(token)
	if err != nil {
		return "", err
	}

	// check user, user+password, or just password for a token
	if j.jwtRegex.MatchString(user) {
		if password == "x-oauth-basic" || // #nosec G101 -- Support blank passwords or magic `x-oauth-basic` passwords, nothing else
			password == "" {
			return user, nil
		}
	} else if j.jwtRegex.MatchString(password) {
		// support passwords and ignore user
		return password, nil
	}

	return "", fmt.Errorf("invalid basic auth token found in authorization header")
}
