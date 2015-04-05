package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
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
	if checkHmac(parts[2], sig) {
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

func checkHmac(input, expected string) bool {
	inputMAC, err1 := base64.URLEncoding.DecodeString(input)
	if err1 == nil {
		expectedMAC, err2 := base64.URLEncoding.DecodeString(expected)
		if err2 == nil {
			return hmac.Equal(inputMAC, expectedMAC)
		}
	}
	return false
}

func encodeAccessToken(aes_cipher cipher.Block, access_token string) (string, error) {
	ciphertext := make([]byte, aes.BlockSize+len(access_token))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to create access code initialization vector")
	}

	stream := cipher.NewCFBEncrypter(aes_cipher, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(access_token))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decodeAccessToken(aes_cipher cipher.Block, encoded_access_token string) (string, error) {
	encrypted_access_token, err := base64.StdEncoding.DecodeString(
		encoded_access_token)

	if err != nil {
		return "", fmt.Errorf("failed to decode access token")
	}

	if len(encrypted_access_token) < aes.BlockSize {
		return "", fmt.Errorf("encrypted access token should be "+
			"at least %d bytes, but is only %d bytes",
			aes.BlockSize, len(encrypted_access_token))
	}

	iv := encrypted_access_token[:aes.BlockSize]
	encrypted_access_token = encrypted_access_token[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(aes_cipher, iv)
	stream.XORKeyStream(encrypted_access_token, encrypted_access_token)

	return string(encrypted_access_token), nil
}

func buildCookieValue(email string, aes_cipher cipher.Block,
	access_token string) (string, error) {
	if aes_cipher == nil {
		return email, nil
	}

	encoded_token, err := encodeAccessToken(aes_cipher, access_token)
	if err != nil {
		return email, fmt.Errorf(
			"error encoding access token for %s: %s", email, err)
	}
	return email + "|" + encoded_token, nil
}

func parseCookieValue(value string, aes_cipher cipher.Block) (email, user,
	access_token string, err error) {
	components := strings.Split(value, "|")
	email = components[0]
	user = strings.Split(email, "@")[0]

	if aes_cipher != nil && len(components) == 2 {
		access_token, err = decodeAccessToken(aes_cipher, components[1])
		if err != nil {
			err = fmt.Errorf(
				"error decoding access token for %s: %s",
				email, err)
		}
	}
	return email, user, access_token, err
}
