package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func Test_EncryptionDecorator(t *testing.T) {
	tests := []struct {
		name    string
		c       ConfigStore
		secret  string
		wantErr bool
	}{
		{
			"encryption decorator no error returned",
			fakeConfigStore{},
			"iuyiuyer8507uy76",
			false,
		},
		{
			"encryption decorator with error returned",
			fakeConfigStore{},
			"iuyiuyer85",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptionDecorator(tt.c, FakeCipher{})
			if err != nil && !tt.wantErr {
				t.Errorf("EncryptionDecorator, got error: '%v'", err)
			}
		})
	}

}

func Test_encryptOrDecryptClientSecret(t *testing.T) {
	f := FakeCipher{}
	tests := []struct {
		name         string
		providerconf []byte
		action       encryptOrDecryptFunc
		want         []byte
		wantErr      bool
	}{
		{
			"with error from unmarshal",
			[]byte("xxxx"),
			nil,
			nil,
			true,
		},
		{
			"with error from action func",
			[]byte("{\"id\":\"xxx'\", \"provider\":\"keycloak\", \"clientSecret\": \"ufhwuif\"}"),
			f.Encrypt,
			nil,
			true,
		},
		{
			"with no error ",
			[]byte("{\"id\":\"xxx'\", \"provider\":\"keycloak\", \"clientSecret\": \"secret\"}"),
			f.Encrypt,
			[]byte("{\"clientSecret\":\"secret\",\"keycloakConfig\":{},\"azureConfig\":{},\"ADFSConfig\":{},\"bitbucketConfig\":{},\"githubConfig\":{},\"gitlabConfig\":{},\"googleConfig\":{},\"oidcConfig\":{},\"loginGovConfig\":{},\"id\":\"xxx'\",\"provider\":\"keycloak\"}"),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptOrDecryptClientSecret(tt.providerconf, tt.action)
			if err == nil && !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encrypt or decrypt client secret func got  = %v, want %v", string(got), string(tt.want))
			} else if err != nil && !tt.wantErr {
				t.Errorf("encrypt or decrypt client secret func returned error: '%v'", err)
			}
		})
	}
}

func Test_Create(t *testing.T) {
	tests := []struct {
		name         string
		providerconf []byte
		createFunc   func(ctx context.Context, id string, providerConfig []byte) error
		wantErr      bool
	}{
		{
			"with error from encrypt client secret func",
			[]byte("xxx"),
			nil,
			true,
		},
		{
			"with error from configstore create func",
			[]byte("{\"id\":\"xxx'\", \"provider\":\"keycloak\", \"clientSecret\": \"secret\"}"),
			func(ctx context.Context, id string, providerConfig []byte) error { return errors.New("err") },
			true,
		},
		{
			"with no error ",
			[]byte("{\"id\":\"xxx'\", \"provider\":\"keycloak\",\"clientSecret\": \"secret\"}"),
			nil,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			en, _ := EncryptionDecorator(fakeConfigStore{CreateFunc: tt.createFunc}, FakeCipher{})
			err := en.Create(context.Background(), "id", tt.providerconf)
			if err != nil && !tt.wantErr {
				t.Errorf("Create returned error: '%v'", err)
			}
		})
	}
}

func Test_Update(t *testing.T) {
	tests := []struct {
		name         string
		providerconf []byte
		updateFunc   func(ctx context.Context, id string, providerConfig []byte) error
		wantErr      bool
	}{
		{
			"with error from encrypt client secret func",
			[]byte("xxx"),
			nil,
			true,
		},
		{
			"with error from configstore update func",
			[]byte("{\"id\":\"xxx'\", \"provider\":\"keycloak\", \"clientSecret\": \"secret\"}"),
			func(ctx context.Context, id string, providerConfig []byte) error { return errors.New("err") },
			true,
		},
		{
			"with no error ",
			[]byte("{\"id\":\"xxx'\", \"provider\":\"keycloak\", \"clientSecret\": \"secret\"}"),
			nil,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			en, _ := EncryptionDecorator(fakeConfigStore{UpdateFunc: tt.updateFunc}, FakeCipher{})
			err := en.Update(context.Background(), "id", tt.providerconf)
			if err != nil && !tt.wantErr {
				t.Errorf("Update returned error: '%v'", err)
			}
		})
	}
}

func Test_Get(t *testing.T) {
	tests := []struct {
		name    string
		getFunc func(ctx context.Context, id string) (string, error)
		want    string
		wantErr bool
	}{
		{
			"with error from encrypt client secret func",
			func(ctx context.Context, id string) (string, error) { return "xxx", nil },
			"",
			true,
		},
		{
			"with error from configstore get func",
			func(ctx context.Context, id string) (string, error) { return "", errors.New("err") },
			"",
			true,
		},
		{
			"with no error ",
			func(ctx context.Context, id string) (string, error) {
				return "{\"id\":\"xxx'\", \"provider\":\"keycloak\", \"clientSecret\":\"4yxujcK/Hg2N7Cr81lLScLV2Lh6r7T9viwB2AYUVT4ujwl4M3g==\" }", nil
			},
			"{\"clientSecret\":\"hf39jrh93uhd93wjd4iwj\",\"keycloakConfig\":{},\"azureConfig\":{},\"ADFSConfig\":{},\"bitbucketConfig\":{},\"githubConfig\":{},\"gitlabConfig\":{},\"googleConfig\":{},\"oidcConfig\":{},\"loginGovConfig\":{},\"id\":\"xxx'\",\"provider\":\"keycloak\"}",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			en, _ := EncryptionDecorator(fakeConfigStore{GetFunc: tt.getFunc}, FakeCipher{}) //"afghjuiektlm87jq")
			got, err := en.Get(context.Background(), "id")
			if err == nil && !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GET got  = %v, want %v", string(got), string(tt.want))
			} else if err != nil && !tt.wantErr {
				t.Errorf("GET returned error: '%v'", err)
			}
		})
	}
}

type FakeCipher struct {
}

func (f FakeCipher) Encrypt(value []byte) ([]byte, error) {
	fmt.Println(string(value))
	if string(value) == "secret" {
		return value, nil
	}
	return nil, errors.New("error from encrypt")
}

func (f FakeCipher) Decrypt(ciphertext []byte) ([]byte, error) {

	return []byte("hf39jrh93uhd93wjd4iwj"), nil
}
