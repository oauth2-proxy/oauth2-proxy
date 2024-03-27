package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func TestCreateProviderConfig(t *testing.T) {

	tests := []struct {
		name         string
		providerConf *options.Provider
		baseurl      string
		wantStatus   int
		wantErr      bool
	}{
		{
			"create provider config with no error",
			&options.Provider{},
			"",
			http.StatusCreated,
			false,
		},
		{
			"create provider config with error",
			&options.Provider{},
			"xuchsdiuch",
			0,
			true,
		},
		{
			"create provider config with error in response",
			&options.Provider{},
			"",
			http.StatusInternalServerError,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := NewMockHTTPServer(http.MethodPost, "/provider", "", nil, tt.wantStatus)
			defer mockServer.Close()

			rc := resty.NewWithClient(mockServer.Client())
			ac := APIClient{
				Client:  rc,
				BaseURL: tt.baseurl,
			}

			if tt.baseurl == "" {
				ac.BaseURL = mockServer.URL
			}
			ctx := context.Background()

			err := ac.CreateProviderConfig(ctx, tt.providerConf)

			if err != nil && !tt.wantErr {
				t.Errorf("create config, got error: '%v'", err)
			}
		})
	}

}

func TestUpdateProviderConfig(t *testing.T) {

	tests := []struct {
		name         string
		providerConf *options.Provider
		baseurl      string
		wantStatus   int
		wantErr      bool
	}{
		{
			"update provider config with no error",
			&options.Provider{},
			"",
			http.StatusAccepted,
			false,
		},
		{
			"update provider config with error",
			&options.Provider{},
			"xuchsdiuch",
			0,
			true,
		},
		{
			"update provider config with error in response",
			&options.Provider{},
			"",
			http.StatusInternalServerError,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := NewMockHTTPServer(http.MethodPut, "/provider", "", nil, tt.wantStatus)
			defer mockServer.Close()

			rc := resty.NewWithClient(mockServer.Client())
			ac := APIClient{
				Client:  rc,
				BaseURL: tt.baseurl,
			}

			if tt.baseurl == "" {
				ac.BaseURL = mockServer.URL
			}
			ctx := context.Background()

			err := ac.UpdateProviderConfig(ctx, tt.providerConf)

			if err != nil && !tt.wantErr {
				t.Errorf("update config, got error: '%v'", err)
			}
		})
	}

}

func TestGetProviderConfig(t *testing.T) {

	tests := []struct {
		name             string
		id               string
		wantproviderConf *options.Provider
		baseurl          string
		wantStatus       int
		wantErr          bool
	}{
		{
			"get provider config with no error",
			"xxx",
			&options.Provider{
				ID: "xxx",
			},
			"",
			http.StatusOK,
			false,
		},
		{
			"get provider config with error",
			"xxx",
			&options.Provider{},
			"xuchsdiuch",
			0,
			true,
		},
		{
			"get provider config with error in response",
			"xxx",
			&options.Provider{},
			"",
			http.StatusInternalServerError,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.wantproviderConf)
			if err != nil {
				t.Errorf("cannot marshal provider config: %v", err)
			}
			mockServer := NewMockHTTPServer(http.MethodGet, "/provider/"+tt.id, "", data, tt.wantStatus)
			defer mockServer.Close()

			rc := resty.NewWithClient(mockServer.Client())
			ac := APIClient{
				Client:  rc,
				BaseURL: tt.baseurl,
			}

			if tt.baseurl == "" {
				ac.BaseURL = mockServer.URL
			}
			ctx := context.Background()

			got, err := ac.GetProviderConfig(ctx, tt.id)

			if err == nil && !tt.wantErr && !reflect.DeepEqual(got, tt.wantproviderConf) {
				t.Errorf("get provider config  = %v, want %v", got, tt.wantproviderConf)
			} else if err != nil && !tt.wantErr {
				t.Errorf("get config, got error: '%v'", err)
			}
		})
	}

}

func TestDeleteProviderConfig(t *testing.T) {

	tests := []struct {
		name       string
		id         string
		baseurl    string
		wantStatus int
		wantErr    bool
	}{
		{
			"delete provider config with no error",
			"xxx",
			"",
			http.StatusNoContent,
			false,
		},
		{
			"delete provider config with error",
			"xxx",
			"xuchsdiuch",
			0,
			true,
		},
		{
			"delete provider config with error in response",
			"xxx",
			"",
			http.StatusInternalServerError,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			mockServer := NewMockHTTPServer(http.MethodDelete, "/provider/"+tt.id, "", nil, tt.wantStatus)
			defer mockServer.Close()

			rc := resty.NewWithClient(mockServer.Client())
			ac := APIClient{
				Client:  rc,
				BaseURL: tt.baseurl,
			}

			if tt.baseurl == "" {
				ac.BaseURL = mockServer.URL
			}
			ctx := context.Background()

			err := ac.DeleteProviderConfig(ctx, tt.id)

			if err != nil && !tt.wantErr {
				t.Errorf("delete config, got error: '%v'", err)
			}
		})
	}

}

func NewMockHTTPServer(httpMethod string, apiRoute string, rawQuery string, expectedResponseBody []byte, statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != httpMethod {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if r.URL.EscapedPath() != apiRoute {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(fmt.Sprintf("Bad ApiPath, '%s'", r.URL.EscapedPath())))
			return
		}
		if r.URL.RawQuery != rawQuery {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(statusCode)
		_, _ = w.Write(expectedResponseBody)
	}))
}
