package main

import (
	"net/http"
)

// SameSiteValue is wrapper for the http.SameSite enum
type SameSiteValue struct {
	sameSite http.SameSite
}

// Get returns a http.SameSite
func (v *SameSiteValue) Get() interface{} {
	return v.sameSite
}

// Set converts the string config value into the SameSiteValue
func (v *SameSiteValue) Set(s string) error {
	switch s {
	case "lax":
		v.sameSite = http.SameSiteLaxMode
	case "strict":
		v.sameSite = http.SameSiteStrictMode
	case "none":
		v.sameSite = http.SameSiteNoneMode
	default:
		v.sameSite = http.SameSiteDefaultMode
	}
	return nil
}

// String returns a string representation of the SameSiteValue
func (v *SameSiteValue) String() string {
	switch v.sameSite {
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteNoneMode:
		return "none"
	case http.SameSiteDefaultMode:
		return ""
	default:
		return ""
	}
}
