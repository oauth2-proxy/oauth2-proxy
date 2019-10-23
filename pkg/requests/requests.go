package requests

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/bitly/go-simplejson"
	"github.com/pusher/oauth2_proxy/pkg/logger"
)

// Request parses the request body into a simplejson.Json object
func Request(req *http.Request) (*simplejson.Json, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Printf("%s %s %s", req.Method, req.URL, err)
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if body != nil {
		defer resp.Body.Close()
	}

	logger.Printf("%d %s %s %s", resp.StatusCode, req.Method, req.URL, body)

	if err != nil {
		return nil, fmt.Errorf("problem reading http request body: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got %d %s", resp.StatusCode, body)
	}

	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling json: %w", err)
	}
	return data, nil
}

// RequestJSON parses the request body into the given interface
func RequestJSON(req *http.Request, v interface{}) error {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Printf("%s %s %s", req.Method, req.URL, err)
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if body != nil {
		defer resp.Body.Close()
	}

	logger.Printf("%d %s %s %s", resp.StatusCode, req.Method, req.URL, body)
	if err != nil {
		return fmt.Errorf("error reading body from http response: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("got %d %s", resp.StatusCode, body)
	}
	return json.Unmarshal(body, v)
}

// RequestUnparsedResponse performs a GET and returns the raw response object
func RequestUnparsedResponse(url string, header http.Header) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error performing get request: %w", err)
	}
	req.Header = header

	return http.DefaultClient.Do(req)
}
