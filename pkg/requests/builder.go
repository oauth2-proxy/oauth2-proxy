package requests

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

// Builder allows users to construct a request and then execute the
// request via Do().
// Do returns a Result which allows the user to get the body,
// unmarshal the body into an interface, or into a simplejson.Json.
type Builder interface {
	WithContext(context.Context) Builder
	WithBody(io.Reader) Builder
	WithMethod(string) Builder
	WithHeaders(http.Header) Builder
	SetHeader(key, value string) Builder
	Do() Result
}

type builder struct {
	context  context.Context
	method   string
	endpoint string
	body     io.Reader
	header   http.Header
	result   *result
}

// New provides a new Builder for the given endpoint.
func New(endpoint string) Builder {
	return &builder{
		endpoint: endpoint,
		method:   "GET",
	}
}

// WithContext adds a context to the request.
// If no context is provided, context.Background() is used instead.
func (r *builder) WithContext(ctx context.Context) Builder {
	r.context = ctx
	return r
}

// WithBody adds a body to the request.
func (r *builder) WithBody(body io.Reader) Builder {
	r.body = body
	return r
}

// WithMethod sets the request method. Defaults to "GET".
func (r *builder) WithMethod(method string) Builder {
	r.method = method
	return r
}

// WithHeaders replaces the request header map with the given header map.
func (r *builder) WithHeaders(header http.Header) Builder {
	r.header = header
	return r
}

// SetHeader sets a single header to the given value.
// May be used to add multiple headers.
func (r *builder) SetHeader(key, value string) Builder {
	if r.header == nil {
		r.header = make(http.Header)
	}
	r.header.Set(key, value)
	return r
}

// Do performs the request and returns the response in its raw form.
// If the request has already been performed, returns the previous result.
// This will not allow you to repeat a request.
func (r *builder) Do() Result {
	if r.result != nil {
		// Request has already been done
		return r.result
	}

	// Must provide a non-nil context to NewRequestWithContext
	if r.context == nil {
		r.context = context.Background()
	}

	return r.do()
}

// do creates the request, executes it with the default client and extracts the
// the body into the response
func (r *builder) do() Result {
	req, err := http.NewRequestWithContext(r.context, r.method, r.endpoint, r.body)
	if err != nil {
		r.result = &result{err: fmt.Errorf("error creating request: %v", err)}
		return r.result
	}
	req.Header = r.header

	httpClient, err := createHttpClient()
	if err != nil {
		r.result = &result{err: fmt.Errorf("error while creating HTTP Client for request: %v", err)}
		return r.result
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		r.result = &result{err: fmt.Errorf("error performing request: %v", err)}
		return r.result
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		r.result = &result{err: fmt.Errorf("error reading response body: %v", err)}
		return r.result
	}

	r.result = &result{response: resp, body: body}
	return r.result
}

const ProxyEnvironmentVariable = "OAUTH2_PROXY_OUTBOUND_PROXY"

// createHttpClient returns a configured http.Client
func createHttpClient() (*http.Client, error) {
	transport, err := createHttpTransport()
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: transport,
	}, nil
}

// creates the http.Transport configuration for the http.Client based on environment variables
func createHttpTransport() (*http.Transport, error) {
	proxyUrlAsString, proxyVariableIsSet := getValueOfEnvironmentVariable(ProxyEnvironmentVariable)
	if proxyVariableIsSet {
		parsedProxyUrl, err := url.Parse(proxyUrlAsString)
		if err != nil {
			return nil, fmt.Errorf("error while parsing %v url: %v", ProxyEnvironmentVariable, err)
		}
		return &http.Transport{
			Proxy: http.ProxyURL(parsedProxyUrl),
		}, nil
	} else {
		// if no proxy config is set then return an empty transport setting so that the default client is used
		return nil, nil
	}
}

// getValueOfEnvironmentVariable returns the value of a given environment variable along with a boolean
// indicating if the variable was set or not
func getValueOfEnvironmentVariable(variableName string) (string, bool) {
	value := os.Getenv(variableName)
	return value, len(value) > 0
}
