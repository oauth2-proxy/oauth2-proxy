package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func validateCookie(cookie *http.Cookie, seed string) (string, bool) {
	// value, timestamp, sig
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 3 {
		return "", false
	}
	sig := cookieSignature(seed, cookie.Name, parts[0], parts[1])
	if parts[2] == sig {
		ts, err := strconv.Atoi(parts[1])
		if err == nil && int64(ts) > time.Now().Add(time.Duration(24)*7*time.Hour*-1).Unix() {
			// it's a valid cookie. now get the contents
			rawValue, err := base64.URLEncoding.DecodeString(parts[0])
			if err == nil {
				return string(rawValue), true
			}
		}
	}
	return "", false
}

func signedCookieValue(seed string, key string, value string) string {
	encodedValue := base64.URLEncoding.EncodeToString([]byte(value))
	timeStr := fmt.Sprintf("%d", time.Now().Unix())
	sig := cookieSignature(seed, key, encodedValue, timeStr)
	cookieVal := fmt.Sprintf("%s|%s|%s", encodedValue, timeStr, sig)
	return cookieVal
}

func cookieSignature(args ...string) string {
	h := hmac.New(sha1.New, []byte(args[0]))
	for _, arg := range args[1:] {
		h.Write([]byte(arg))
	}
	var b []byte
	b = h.Sum(b)
	return base64.URLEncoding.EncodeToString(b)
}
