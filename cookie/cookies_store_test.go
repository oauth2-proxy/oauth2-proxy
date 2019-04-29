package cookie

import (
	"encoding/base64"
	"net/http"
	"reflect"
	"testing"

	"github.com/alicebob/miniredis"
	"github.com/go-redis/redis"
	"github.com/stretchr/testify/assert"
)

func NewTestRedis() *redis.Client {
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	client.Ping()
	return client
}

func TestRedisCookieStore(t *testing.T) {
	client := NewTestRedis()
	secretString, _ := base64.RawURLEncoding.DecodeString("MTIzNDU2Nzg5MDEyMzQ1Ng")
	testCipher, _ := NewCipher(secretString)

	firstValue := "1234567890"
	responseCookie := &http.Cookie{Value: firstValue}

	store := &RedisCookieStore{
		Client: client,
		Block:  testCipher.Block,
		Prefix: "oauth2_proxy",
	}

	// Test Store
	ticket, err := store.Store(responseCookie, nil)
	if err != nil {
		t.Errorf("RedisCookieStore.Store() error = %v", err)
		return
	}

	// Test Load
	ticketCookie := &http.Cookie{Value: ticket}
	loadedValue, err := store.Load(ticketCookie)
	if err != nil {
		t.Errorf("RedisCookieStore.Load() error = %v", err)
		return
	}

	if loadedValue != firstValue {
		t.Errorf("RedisCookieStore.Store() = %v, expected %v", loadedValue, firstValue)
	}

	// Test replacement
	secondValue := "0987654321"
	responseCookie = &http.Cookie{Value: secondValue}

	_, err = store.Store(responseCookie, ticketCookie)
	if err != nil {
		t.Errorf("RedisCookieStore.Store() error = %v", err)
		return
	}

	newLoadedValue, err := store.Load(ticketCookie)
	if err != nil {
		t.Errorf("RedisCookieStore.Load() error = %v", err)
		return
	}

	if newLoadedValue != secondValue {
		t.Errorf("RedisCookieStore.Store() = %v, expected %v", newLoadedValue, secondValue)
	}

	// Test Clearing an actual value
	wasDeleted, err := store.Clear(ticketCookie)
	if err != nil {
		t.Errorf("RedisCookieStore.Clear() error = %v", err)
		return
	}
	assert.Equal(t, true, wasDeleted)

	// Test clearing with no value
	wasDeleted, err = store.Clear(ticketCookie)
	if err != nil {
		t.Errorf("RedisCookieStore.Clear() error = %v", err)
		return
	}
	assert.Equal(t, false, wasDeleted)
}

func Test_parseCookieTicket(t *testing.T) {
	type args struct {
		expectedPrefix string
		ticket         string
	}
	tests := []struct {
		name    string
		args    args
		handle  string
		iv      []byte
		wantErr bool
	}{
		{
			"Bad Prefix (not matching), Good ID, Good IV",
			args{"oauth2_proxy",
				"_oauth2_proxy-eb1bc8906a3111e98d4fa45e60f3cffd.MTIzNDU2Nzg5MDEyMzQ1Ng",
			},
			"",
			nil,
			true,
		},
		{
			"Good Prefix, Bad ID (not hex), Good IV",
			args{"oauth2_proxy",
				"oauth2_proxy-foobar1234.MTIzNDU2Nzg5MDEyMzQ1Ng",
			},
			"",
			nil,
			true,
		},
		{
			"Good Prefix, Good ID, Bad IV (not URL safe)",
			args{"oauth2_proxy",
				"oauth2_proxy-eb1bc8906a3111e98d4fa45e60f3cffd.+MTIzNDU2Nzg5MDEyMzQ1Ng",
			},
			"",
			nil,
			true,
		},
		{
			"Good Prefix, Good ID, Good IV",
			args{"oauth2_proxy",
				"oauth2_proxy-eb1bc8906a3111e98d4fa45e60f3cffd.MTIzNDU2Nzg5MDEyMzQ1Ng",
			},
			"oauth2_proxy-eb1bc8906a3111e98d4fa45e60f3cffd",
			[]byte("1234567890123456"),
			false,
		},
		{
			"Good Prefix with dash, Good ID, Good IV",
			args{"oauth2-proxy",
				"oauth2-proxy-eb1bc8906a3111e98d4fa45e60f3cffd.MTIzNDU2Nzg5MDEyMzQ1Ng",
			},
			"oauth2-proxy-eb1bc8906a3111e98d4fa45e60f3cffd",
			[]byte("1234567890123456"),
			false,
		},
		{
			"Good Prefix with period, Good ID, Good IV",
			args{"oauth2.proxy",
				"oauth2.proxy-eb1bc8906a3111e98d4fa45e60f3cffd.MTIzNDU2Nzg5MDEyMzQ1Ng",
			},
			"oauth2.proxy-eb1bc8906a3111e98d4fa45e60f3cffd",
			[]byte("1234567890123456"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookieHandle, iv, err := parseCookieTicket(tt.args.expectedPrefix, tt.args.ticket)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCookieTicket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if cookieHandle != tt.handle {
				t.Errorf("parseCookieTicket() cookieHandle = %v, handle %v", cookieHandle, tt.handle)
			}

			if !reflect.DeepEqual(iv, tt.iv) {
				t.Errorf("parseCookieTicket() iv = %v, iv %v", iv, tt.iv)
			}
		})
	}
}
