package requests

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bitly/go-simplejson"
)

// Result is the result of a request created by a Builder
type Result interface {
	Error() error
	StatusCode() int
	Headers() http.Header
	Body() []byte
	UnmarshalInto(interface{}) error
	UnmarshalJSON() (*simplejson.Json, error)
}

type result struct {
	err      error
	response *http.Response
	body     []byte
}

// Error returns an error from the result if present
func (r *result) Error() error {
	return r.err
}

// StatusCode returns the response's status code
func (r *result) StatusCode() int {
	if r.response != nil {
		return r.response.StatusCode
	}
	return 0
}

// Headers returns the response's headers
func (r *result) Headers() http.Header {
	if r.response != nil {
		return r.response.Header
	}
	return nil
}

// Body returns the response's body
func (r *result) Body() []byte {
	return r.body
}

// UnmarshalInto attempts to unmarshal the response into the the given interface.
// The response body is assumed to be JSON.
// The response must have a 200 status otherwise an error will be returned.
func (r *result) UnmarshalInto(into interface{}) error {
	body, err := r.getBodyForUnmarshal()
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("error unmarshalling body: %v", err)
	}

	return nil
}

// UnmarshalJSON performs the request and attempts to unmarshal the response into a
// simplejson.Json. The response body is assume to be JSON.
// The response must have a 200 status otherwise an error will be returned.
func (r *result) UnmarshalJSON() (*simplejson.Json, error) {
	body, err := r.getBodyForUnmarshal()
	if err != nil {
		return nil, err
	}

	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, fmt.Errorf("error reading json: %v", err)
	}
	return data, nil
}

// getBodyForUnmarshal returns the body if there wasn't an error and the status
// code was 200.
func (r *result) getBodyForUnmarshal() ([]byte, error) {
	if r.Error() != nil {
		return nil, r.Error()
	}

	// Only unmarshal body if the response was successful
	if r.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status \"%d\": %s", r.StatusCode(), r.Body())
	}

	return r.Body(), nil
}
