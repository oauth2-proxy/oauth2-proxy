package util

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/spf13/cast"
)

// ClaimExtractor is used to extract claim values from an ID Token, or, if not
// present, from the profile URL.
type ClaimExtractor interface {
	// GetClaim fetches a named claim and returns the value.
	GetClaim(claim string) (interface{}, bool, error)

	// GetClaimInto fetches a named claim and puts the value into the destination.
	GetClaimInto(claim string, dst interface{}) (bool, error)
}

// NewClaimExtractor constructs a new ClaimExtractor from the raw ID Token.
// If needed, it will use the profile URL to look up a claim if it isn't present
// within the ID Token.
func NewClaimExtractor(ctx context.Context, idToken string, profileURL *url.URL, profileRequestHeaders http.Header) (ClaimExtractor, error) {
	payload, err := parseJWT(idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID Token: %v", err)
	}

	tokenClaims, err := simplejson.NewJson(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID Token payload: %v", err)
	}

	return &claimExtractor{
		ctx:            ctx,
		profileURL:     profileURL,
		requestHeaders: profileRequestHeaders,
		tokenClaims:    tokenClaims,
	}, nil
}

// claimExtractor implements the ClaimExtractor interface
type claimExtractor struct {
	profileURL     *url.URL
	ctx            context.Context
	requestHeaders map[string][]string
	tokenClaims    *simplejson.Json
	profileClaims  *simplejson.Json
}

// GetClaim will return the value claim if it exists.
// It will only return an error if the profile URL needs to be fetched due to
// the claim not being present in the ID Token.
func (c *claimExtractor) GetClaim(claim string) (interface{}, bool, error) {
	if claim == "" {
		return nil, false, nil
	}

	if value := getClaimFrom(claim, c.tokenClaims); value != nil {
		return value, true, nil
	}

	if c.profileClaims == nil {
		profileClaims, err := c.loadProfileClaims()
		if err != nil {
			return nil, false, fmt.Errorf("failed to fetch claims from profile URL: %v", err)
		}

		c.profileClaims = profileClaims
	}

	if value := getClaimFrom(claim, c.profileClaims); value != nil {
		return value, true, nil
	}

	return nil, false, nil
}

// loadProfileClaims will fetch the profileURL using the provided headers as
// authentication.
func (c *claimExtractor) loadProfileClaims() (*simplejson.Json, error) {
	if c.profileURL == nil || c.profileURL.String() == "" || c.requestHeaders == nil {
		// When no profileURL is set, we return a non-empty map so that
		// we don't attempt to populate the profile claims again.
		// If there are no headers, the request would be unauthorized so we also skip
		// in this case too.
		return simplejson.New(), nil
	}

	claims, err := requests.New(c.profileURL.String()).
		WithContext(c.ctx).
		WithHeaders(c.requestHeaders).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		return nil, fmt.Errorf("error making request to profile URL: %v", err)
	}

	return claims, nil
}

// GetClaimInto loads a claim and places it into the destination interface.
// This will attempt to coerce the claim into the specified type.
// If it cannot be coerced, an error may be returned.
func (c *claimExtractor) GetClaimInto(claim string, dst interface{}) (bool, error) {
	value, exists, err := c.GetClaim(claim)
	if err != nil {
		return false, fmt.Errorf("could not get claim %q: %v", claim, err)
	}
	if !exists {
		return false, nil
	}
	if err := coerceClaim(value, dst); err != nil {
		return false, fmt.Errorf("could no coerce claim: %v", err)
	}

	return true, nil
}

// This has been copied from https://github.com/coreos/go-oidc/blob/8d771559cf6e5111c9b9159810d0e4538e7cdc82/verify.go#L120-L130
// We use it to grab the raw ID Token payload so that we can parse it into the JSON library.
func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}

// getClaimFrom gets a claim from a Json object.
// It can accept either a single claim name or a json path. The claim is always evaluated first as a single claim name.
// Paths with indexes are not supported.
func getClaimFrom(claim string, src *simplejson.Json) interface{} {
	if value, ok := src.CheckGet(claim); ok {
		return value.Interface()
	}
	claimParts := strings.Split(claim, ".")
	return src.GetPath(claimParts...).Interface()
}

// coerceClaim tries to convert the value into the destination interface type.
// If it can convert the value, it will then store the value in the destination
// interface.
func coerceClaim(value, dst interface{}) error {
	switch d := dst.(type) {
	case *string:
		str, err := toString(value)
		if err != nil {
			return fmt.Errorf("could not convert value to string: %v", err)
		}
		*d = str
	case *[]string:
		strSlice, err := toStringSlice(value)
		if err != nil {
			return fmt.Errorf("could not convert value to string slice: %v", err)
		}
		*d = strSlice
	case *bool:
		*d = cast.ToBool(value)
	default:
		return fmt.Errorf("unknown type for destination: %T", dst)
	}
	return nil
}

// toStringSlice converts an interface (either a slice or single value) into
// a slice of strings.
func toStringSlice(value interface{}) ([]string, error) {
	var sliceValues []interface{}
	switch v := value.(type) {
	case []interface{}:
		sliceValues = v
	case interface{}:
		sliceValues = []interface{}{v}
	default:
		sliceValues = cast.ToSlice(value)
	}

	out := []string{}
	for _, v := range sliceValues {
		str, err := toString(v)
		if err != nil {
			return nil, fmt.Errorf("could not convert slice entry to string %v: %v", v, err)
		}
		out = append(out, str)
	}
	return out, nil
}

// toString coerces a value into a string.
// If it is non-string, marshal it into JSON.
func toString(value interface{}) (string, error) {
	if str, err := cast.ToStringE(value); err == nil {
		return str, nil
	}

	jsonStr, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(jsonStr), nil
}
