package decorators

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	tenantutils "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/tenant/utils"
)

func TestTenantIdValidator(t *testing.T) {
	tests := []struct {
		name string
		s    sessionsapi.SessionStore
		want sessionsapi.SessionStore
	}{
		{
			"tenantid validator",
			&tenantIDValidator{},
			&tenantIDValidator{
				&tenantIDValidator{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TenantIDValidator(tt.s)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("tenantid validator  = %v, want %v", got, tt.want)
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
		tiv     *tenantIDValidator
		want    string
		wantErr bool
	}{
		{
			"validateTenantId save with no error",
			requestWithTenantIDContext("tid"),
			&tenantIDValidator{
				&fakeSessionStore{
					SaveFunc: func(_ http.ResponseWriter, _ *http.Request, s *sessionsapi.SessionState) error {
						got = s.TenantID
						return nil
					},
				},
			},
			"tid",
			false,
		},
		{
			"validateTenantId save with error",
			&http.Request{},
			&tenantIDValidator{
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
				t.Errorf("validatetenantid save  = %v, want %v", got, tt.want)
			} else if err != nil && !tt.wantErr {
				t.Errorf("validatetenantid save error returned  = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		req     *http.Request
		want    *sessionsapi.SessionState
		tiv     *tenantIDValidator
		wantErr bool
	}{
		{
			"load with no error",
			requestWithTenantIDContext("dummyid"),
			&sessionsapi.SessionState{
				TenantID: "dummyid",
			},
			&tenantIDValidator{
				&fakeSessionStore{
					LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
						return &sessionsapi.SessionState{TenantID: "dummyid"}, nil
					},
				},
			},
			false,
		},
		{
			"load with error returned due to tenantid does not match",
			requestWithTenantIDContext("dummy"),
			nil,
			&tenantIDValidator{
				&fakeSessionStore{
					LoadFunc: func(req *http.Request) (*sessionsapi.SessionState, error) {
						return &sessionsapi.SessionState{TenantID: "xxx"}, nil
					},
				},
			},
			true,
		},
		{
			"load with error returned from session store load",
			&http.Request{},
			nil,
			&tenantIDValidator{
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
				t.Errorf("tenantid load  = %v, want %v", got, tt.want)
			} else if err != nil && !tt.wantErr {
				t.Errorf("tenantid load, got error: '%v'", err)
			}
		})
	}

}

func requestWithTenantIDContext(tid string) *http.Request {
	req := &http.Request{}
	ctx := tenantutils.AppendToContext(req.Context(), tid)

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
