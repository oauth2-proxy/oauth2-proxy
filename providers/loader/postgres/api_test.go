package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func TestCreateHandler(t *testing.T) {
	tests := []struct {
		name       string
		body       *options.Provider
		mockCreate func(ctx context.Context, id string, providerConfig []byte) error
		wantErr    bool
	}{
		{
			"create with no error",
			&options.Provider{
				ID:   "xxx",
				Type: options.KeycloakProvider,
			},
			func(ctx context.Context, id string, providerConfig []byte) error {
				return nil
			},
			false,
		},
		{
			"create with error from validate",
			&options.Provider{
				Type: options.KeycloakProvider,
			},
			func(ctx context.Context, id string, providerConfig []byte) error {
				return nil
			},
			true,
		},
		{
			"create with error from config store",
			&options.Provider{
				ID:   "xxx",
				Type: options.KeycloakProvider,
			},
			func(ctx context.Context, id string, providerConfig []byte) error {
				return fmt.Errorf("error")
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Errorf("cannot marshal req body")
			}

			req := httptest.NewRequest(http.MethodPost, "/oauth/provider", bytes.NewBuffer(body))
			w := httptest.NewRecorder()
			api := API{
				configStore: fakeConfigStore{
					CreateFunc: tt.mockCreate,
				},
				conf: options.API{
					PathPrefix: "/oauth",
				},
			}
			api.CreateHandler(w, req)
			res := w.Result()
			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("expected error to be nil got %v", err)
			}

			if res.StatusCode != http.StatusCreated && !tt.wantErr {
				t.Errorf("the func returned: %v, code : %d", string(data), res.StatusCode)
			}
		})
	}
}

func TestGetHandler(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		mockGet func(ctx context.Context, id string) (string, error)
		wantErr bool
	}{
		{
			"get with no error",
			"xxx",
			func(ctx context.Context, id string) (string, error) {
				return "success", nil
			},
			false,
		},
		{
			"get with error from config store",
			"xxx",
			func(ctx context.Context, id string) (string, error) {
				return "", fmt.Errorf("error")
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			req := httptest.NewRequest(http.MethodGet, "/oauth/provider/"+tt.id, nil)
			w := httptest.NewRecorder()
			api := API{
				configStore: fakeConfigStore{
					GetFunc: tt.mockGet,
				},
				conf: options.API{
					PathPrefix: "/oauth",
				},
			}
			api.GetHandler(w, req)
			res := w.Result()
			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("expected error to be nil got %v", err)
			}

			if res.StatusCode != http.StatusOK && !tt.wantErr {
				t.Errorf("the func returned: %v, code : %d", string(data), res.StatusCode)
			}
		})
	}
}

func TestDeleteHandler(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		mockDelete func(ctx context.Context, id string) error
		wantErr    bool
	}{
		{
			"delete with no error",
			"xxx",
			func(ctx context.Context, id string) error {
				return nil
			},
			false,
		},
		{
			"delete with error from config store",
			"xxx",
			func(ctx context.Context, id string) error {
				return fmt.Errorf("error")
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			req := httptest.NewRequest(http.MethodDelete, "/oauth/provider/"+tt.id, nil)
			w := httptest.NewRecorder()
			api := API{
				configStore: fakeConfigStore{
					DeleteFunc: tt.mockDelete,
				},
				conf: options.API{
					PathPrefix: "/oauth",
				},
			}
			api.DeleteHandler(w, req)
			res := w.Result()
			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("expected error to be nil got %v", err)
			}

			if res.StatusCode != http.StatusNoContent && !tt.wantErr {
				t.Errorf("the func returned: %v, code : %d", string(data), res.StatusCode)
			}
		})
	}
}

func TestUpdateHandler(t *testing.T) {
	tests := []struct {
		name       string
		body       *options.Provider
		mockUpdate func(ctx context.Context, id string, providerConfig []byte) error
		wantErr    bool
	}{
		{
			"update with no error",
			&options.Provider{
				ID:   "xxx",
				Type: options.KeycloakProvider,
			},
			func(ctx context.Context, id string, providerConfig []byte) error {
				return nil
			},
			false,
		},
		{
			"update with error from validate",
			&options.Provider{
				Type: options.KeycloakProvider,
			},
			func(ctx context.Context, id string, providerConfig []byte) error {
				return nil
			},
			true,
		},
		{
			"update with error from config store",
			&options.Provider{
				ID:   "xxx",
				Type: options.KeycloakProvider,
			},
			func(ctx context.Context, id string, providerConfig []byte) error {
				return fmt.Errorf("error")
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Errorf("cannot marshal req body")
			}

			req := httptest.NewRequest(http.MethodPut, "/oauth/provider", bytes.NewBuffer(body))
			w := httptest.NewRecorder()
			api := API{
				configStore: fakeConfigStore{
					UpdateFunc: tt.mockUpdate,
				},
				conf: options.API{
					PathPrefix: "/oauth",
				},
			}
			api.UpdateHandler(w, req)
			res := w.Result()
			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("expected error to be nil got %v", err)
			}

			if res.StatusCode != http.StatusAccepted && !tt.wantErr {
				t.Errorf("the func returned: %v, code : %d", string(data), res.StatusCode)
			}
		})
	}
}

func TestValidateProviderConfig(t *testing.T) {
	tests := []struct {
		name         string
		providerConf []byte
		wantErr      bool
	}{
		{
			"validate with no error",
			[]byte("{\"id\":\"xxx\", \"provider\":\"keycloak\"}"),
			false,
		},
		{
			"validate werrReader(0)ith error from json.unmarshal",
			[]byte("{\"id\": \"xxx\", err:?okosfko}"),
			true,
		},
		{
			"validate with error no id",
			[]byte("{}"),
			true,
		},
		{
			"validate with error from new provider",
			[]byte("{\"id\": \"xxx\"}"),
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := API{}

			_, err := api.validateProviderConfig(tt.providerConf)

			if err != nil && !tt.wantErr {
				t.Errorf("New config loader, got error: '%v'", err)
			}
		})
	}

}
