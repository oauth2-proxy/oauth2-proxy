package requests

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	r.header = header.Clone()
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

	resp, err := DefaultHTTPClient.Do(req)
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
