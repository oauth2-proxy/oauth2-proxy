package upstream

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/pagewriter"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// newRewritePath creates a new middleware that will rewrite the request URI
// path before handing the request to the next server.
func newRewritePath(rewriteRegExp *regexp.Regexp, rewriteTarget string, writer pagewriter.Writer) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return rewritePath(rewriteRegExp, rewriteTarget, writer, next)
	}
}

// rewritePath uses the regexp to rewrite the request URI based on the provided
// rewriteTarget.
func rewritePath(rewriteRegExp *regexp.Regexp, rewriteTarget string, writer pagewriter.Writer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		reqURL, err := url.ParseRequestURI(req.RequestURI)
		if err != nil {
			logger.Errorf("could not parse request URI: %v", err)
			writer.WriteErrorPage(rw, pagewriter.ErrorPageOpts{
				Status:    http.StatusInternalServerError,
				RequestID: middleware.GetRequestScope(req).RequestID,
				AppError:  fmt.Sprintf("Could not parse request URI: %v", err),
			})
			return
		}

		// Use the regex to rewrite the request path before proxying to the upstream.
		newURI := rewriteRegExp.ReplaceAllString(reqURL.Path, rewriteTarget)
		reqURL.Path, reqURL.RawQuery, err = splitPathAndQuery(reqURL.Query(), newURI)
		if err != nil {
			logger.Errorf("could not parse rewrite URI: %v", err)
			writer.WriteErrorPage(rw, pagewriter.ErrorPageOpts{
				Status:    http.StatusInternalServerError,
				RequestID: middleware.GetRequestScope(req).RequestID,
				AppError:  fmt.Sprintf("Could not parse rewrite URI: %v", err),
			})
			return
		}

		req.RequestURI = reqURL.String()
		req.URL.Path = reqURL.Path // set path for websocket connections
		next.ServeHTTP(rw, req)
	})
}

// splitPathAndQuery splits the rewritten path into the URL Path and the URL
// raw query. Any rewritten query values are appended to the original query
// values.
// This relies on the underlying URL library to encode the query string.
// For duplicate values it appends each as a separate value, e.g. ?foo=bar&foo=baz.
func splitPathAndQuery(originalQuery url.Values, raw string) (string, string, error) {
	s := strings.SplitN(raw, "?", 2)
	if len(s) == 1 {
		return s[0], originalQuery.Encode(), nil
	}

	queryValues, err := url.ParseQuery(s[1])
	if err != nil {
		return "", "", nil
	}

	for key, values := range queryValues {
		for _, value := range values {
			originalQuery.Add(key, value)
		}
	}

	return s[0], originalQuery.Encode(), nil
}
