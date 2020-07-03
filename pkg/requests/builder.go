package requests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/bitly/go-simplejson"
)

// Builder allows users to construct a request and then either get the requests
// response via Do(), parse the response into a simplejson.Json via JSON(),
// or to parse the json response into an object via UnmarshalInto().
type Builder interface {
	WithContext(context.Context) Builder
	WithBody(io.Reader) Builder
	WithMethod(string) Builder
	WithHeaders(http.Header) Builder
	SetHeader(key, value string) Builder
	Do() (*http.Response, error)
	UnmarshalInto(interface{}) error
	UnmarshalJSON() (*simplejson.Json, error)
}

type builder struct {
	context  context.Context
	method   string
	endpoint string
	body     io.Reader
	header   http.Header
	response *http.Response
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
func (r *builder) Do() (*http.Response, error) {
	if r.response != nil {
		// Request has already been done
		return r.response, nil
	}

	// Must provide a non-nil context to NewRequestWithContext
	if r.context == nil {
		r.context = context.Background()
	}

	req, err := http.NewRequestWithContext(r.context, r.method, r.endpoint, r.body)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	req.Header = r.header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing request: %v", err)
	}

	r.response = resp
	return resp, nil
}

// UnmarshalInto performs the request and attempts to unmarshal the response into the
// the given interface. The response body is assumed to be JSON.
// The response must have a 200 status otherwise an error will be returned.
func (r *builder) UnmarshalInto(into interface{}) error {
	resp, err := r.Do()
	if err != nil {
		return err
	}

	return UnmarshalInto(resp, into)
}

// UnmarshalJSON performs the request and attempts to unmarshal the response into a
// simplejson.Json. The response body is assume to be JSON.
// The response must have a 200 status otherwise an error will be returned.
func (r *builder) UnmarshalJSON() (*simplejson.Json, error) {
	resp, err := r.Do()
	if err != nil {
		return nil, err
	}

	body, err := getResponseBody(resp)
	if err != nil {
		return nil, err
	}

	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, fmt.Errorf("error reading json: %v", err)
	}
	return data, nil
}

// UnmarshalInto attempts to unmarshal the response into the the given interface.
// The response body is assumed to be JSON.
// The response must have a 200 status otherwise an error will be returned.
func UnmarshalInto(resp *http.Response, into interface{}) error {
	body, err := getResponseBody(resp)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("error unmarshalling body: %v", err)
	}

	return nil
}

// getResponseBody extracts the response body, but will only return the body
// if the response was successful.
func getResponseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	// Only unmarshal body if the response was successful
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status \"%d\": %s", resp.StatusCode, body)
	}

	return body, nil
}
