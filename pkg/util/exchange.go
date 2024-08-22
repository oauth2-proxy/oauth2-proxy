package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

type Token struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiry       time.Time
	Raw          interface{}
}

type tokenJSON struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    expirationTime `json:"expires_in"` // at least PayPal returns string, while most return number
}

func (e *tokenJSON) expiry() (t time.Time) {
	if v := e.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}

type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	if i > math.MaxInt32 {
		i = math.MaxInt32
	}
	*e = expirationTime(i)
	return nil
}

func (t *Token) Extra(key string) interface{} {
	if raw, ok := t.Raw.(map[string]interface{}); ok {
		return raw[key]
	}

	vals, ok := t.Raw.(url.Values)
	if !ok {
		return nil
	}

	v := vals.Get(key)
	switch s := strings.TrimSpace(v); strings.Count(s, ".") {
	case 0: // Contains no "."; try to parse as int
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
	case 1: // Contains a single "."; try to parse as float
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}

	return v
}

func UnmarshalToken(Headers http.Header, body []byte) (*Token, error) {
	var token *Token
	if !gjson.ValidBytes(body) {
		return nil, fmt.Errorf("invalid JSON format in response body , get %v", string(body))
	}
	content, _, _ := mime.ParseMediaType(Headers.Get("Content-Type"))

	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		token = &Token{
			AccessToken:  vals.Get("access_token"),
			TokenType:    vals.Get("token_type"),
			RefreshToken: vals.Get("refresh_token"),
			Raw:          vals,
		}
		e := vals.Get("expires_in")
		expires, _ := strconv.Atoi(e)
		if expires != 0 {
			token.Expiry = time.Now().Add(time.Duration(expires) * time.Second)
		}
	default:
		var tj tokenJSON
		if err := json.Unmarshal(body, &tj); err != nil {
			return nil, err
		}
		token = &Token{
			AccessToken:  tj.AccessToken,
			TokenType:    tj.TokenType,
			RefreshToken: tj.RefreshToken,
			Expiry:       tj.expiry(),
			Raw:          make(map[string]interface{}),
		}
		if err := json.Unmarshal(body, &token.Raw); err != nil {
			return nil, err
		}

		// no error checks for optional fields
	}
	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}
	return token, nil
}
