package decorators

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/utils"
)

func TestProviderIdValidator(t *testing.T) {
	tests := []struct {
		name string
		s    sessionsapi.SessionStore
		want sessionsapi.SessionStore
	}{
		{
			"providerid validator",
			&providerIDValidator{},
			&providerIDValidator{
				&providerIDValidator{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProviderIDValidator(tt.s)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("providerid validator  = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSave(t *testing.T) {
	var got string
	rw := httptest.NewRecorder()
	tests := []struct {
		name    string
		req     *http.Request
		tiv     *providerIDValidator
		want    string
		wantErr bool
	}{
		{
			"validateProviderId save with no error",
			requestWithProviderIDContext("tid"),
			&providerIDValidator{
				&fakeSessionStore{
					SaveFunc: func(_ http.ResponseWriter, _ *http.Request, s *sessionsapi.SessionState) error {
						got = s.ProviderID
						return nil
					},
				},
			},
			"tid",
			false,
		},
		{
			"validateProviderId save with error",
			&http.Request{},
			&providerIDValidator{
				&fakeSessionStore{
					SaveFunc: func(_ http.ResponseWriter, _ *http.Request, s *sessionsapi.SessionState) error {
						return fmt.Errorf("error")
					},
				},
			},
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got = ""
			err := tt.tiv.Save(rw, tt.req, &sessionsapi.SessionState{})
			if err == nil && !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateproviderid save  = %v, want %v", got, tt.want)
			} else if err != nil && !tt.wantErr {
				t.Errorf("validateproviderid save error returned  = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		req     *http.Request
		want    *sessionsapi.SessionState
		tiv     *providerIDValidator
		wantErr bool
	}{
		{
			"load with no error",
			requestWithProviderIDContext("dummyid"),
			&sessionsapi.SessionState{
				ProviderID: "dummyid",
			},
			&providerIDValidator{
				&fakeSessionStore{
					LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
						return &sessionsapi.SessionState{ProviderID: "dummyid"}, nil
					},
				},
			},
			false,
		},
		{
			"load with error returned due to providerid does not match",
			requestWithProviderIDContext("dummy"),
			nil,
			&providerIDValidator{
				&fakeSessionStore{
					LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
						return &sessionsapi.SessionState{ProviderID: "xxx"}, nil
					},
				},
			},
			true,
		},
		{
			"load with error returned from session store load",
			&http.Request{},
			nil,
			&providerIDValidator{
				&fakeSessionStore{
					LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
						return nil, fmt.Errorf("error")
					},
				},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.tiv.Load(tt.req)

			if err == nil && !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("providerid load  = %v, want %v", got, tt.want)
			} else if err != nil && !tt.wantErr {
				t.Errorf("providerid load, got error: '%v'", err)
			}
		})
	}

}

func requestWithProviderIDContext(tid string) *http.Request {
	req := &http.Request{}
	ctx := utils.AppendToContext(req.Context(), tid)

	return req.WithContext(ctx)
}

type fakeSessionStore struct {
	SaveFunc  func(http.ResponseWriter, *http.Request, *sessionsapi.SessionState) error
	LoadFunc  func(req *http.Request) (*sessionsapi.SessionState, error)
	ClearFunc func(rw http.ResponseWriter, req *http.Request) error
}

func (f *fakeSessionStore) Save(rw http.ResponseWriter, req *http.Request, s *sessionsapi.SessionState) error {
	if f.SaveFunc != nil {
		return f.SaveFunc(rw, req, s)
	}
	return nil
}
func (f *fakeSessionStore) Load(req *http.Request) (*sessionsapi.SessionState, error) {
	if f.LoadFunc != nil {
		return f.LoadFunc(req)
	}
	return nil, nil
}

func (f *fakeSessionStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	if f.ClearFunc != nil {
		return f.ClearFunc(rw, req)
	}
	return nil
}

func (f *fakeSessionStore) VerifyConnection(_ context.Context) error {
	return nil
}
