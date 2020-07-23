package middleware

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/coreos/go-oidc"
	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

const jwtRegexFormat = `^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+$`

func NewJwtSessionLoader(sessionLoaders []middlewareapi.TokenToSessionLoader) alice.Constructor {
	for i, loader := range sessionLoaders {
		if loader.TokenToSession == nil {
			sessionLoaders[i] = middlewareapi.TokenToSessionLoader{
				Verifier:       loader.Verifier,
				TokenToSession: createSessionStateFromBearerToken,
			}
		}
	}

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
	sessionLoaders []middlewareapi.TokenToSessionLoader
}

// loadSession attempts to load a session from a JWT stored in an Authorization
// header within the request.
// If no authorization header is found, or the header is invalid, no session
// will be loaded and the request will be passed to the next handler.
// If a session was loaded by a previous handler, it will not be replaced.
func (j *jwtSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		session, err := j.getJwtSession(req)
		if err != nil {
			logger.Printf("Error retrieving session from token in Authorization header: %v", err)
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

	rawBearerToken, err := j.findBearerTokenFromHeader(auth)
	if err != nil {
		return nil, err
	}

	for _, loader := range j.sessionLoaders {
		bearerToken, err := loader.Verifier.Verify(req.Context(), rawBearerToken)
		if err == nil {
			// The token was verified, convert it to a session
			return loader.TokenToSession(req.Context(), rawBearerToken, bearerToken)
		}
	}

	return nil, fmt.Errorf("unable to verify jwt token: %q", req.Header.Get("Authorization"))
}

// findBearerTokenFromHeader finds a valid JWT token from the Authorization header of a given request.
func (j *jwtSessionLoader) findBearerTokenFromHeader(header string) (string, error) {
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
		// Support blank passwords or magic `x-oauth-basic` passwords - nothing else
		if password == "" || password == "x-oauth-basic" {
			return user, nil
		}
	} else if j.jwtRegex.MatchString(password) {
		// support passwords and ignore user
		return password, nil
	}

	return "", fmt.Errorf("invalid basic auth token found in authorization header")
}

// createSessionStateFromBearerToken is a default implementation for converting
// a JWT into a session state.
func createSessionStateFromBearerToken(ctx context.Context, rawIDToken string, idToken *oidc.IDToken) (*sessionsapi.SessionState, error) {
	var claims struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		Verified          *bool  `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse bearer token claims: %v", err)
	}

	if claims.Email == "" {
		claims.Email = claims.Subject
	}

	if claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	newSession := &sessionsapi.SessionState{
		Email:             claims.Email,
		User:              claims.Subject,
		PreferredUsername: claims.PreferredUsername,
		AccessToken:       rawIDToken,
		IDToken:           rawIDToken,
		RefreshToken:      "",
		ExpiresOn:         &idToken.Expiry,
	}

	return newSession, nil
}
