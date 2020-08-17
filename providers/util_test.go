package providers

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
)

func TestMakeAuhtorizationHeader(t *testing.T) {
	testCases := []struct {
		name         string
		prefix       string
		token        string
		extraHeaders map[string]string
	}{
		{
			name:         "With an empty prefix, token and no additional headers",
			prefix:       "",
			token:        "",
			extraHeaders: nil,
		},
		{
			name:         "With a Bearer token type",
			prefix:       tokenTypeBearer,
			token:        "abcdef",
			extraHeaders: nil,
		},
		{
			name:         "With a Token token type",
			prefix:       tokenTypeToken,
			token:        "123456",
			extraHeaders: nil,
		},
		{
			name:   "With a Bearer token type and Accept application/json",
			prefix: tokenTypeToken,
			token:  "abc",
			extraHeaders: map[string]string{
				acceptHeader: acceptApplicationJSON,
			},
		},
		{
			name:   "With a Bearer token type and multiple headers",
			prefix: tokenTypeToken,
			token:  "123",
			extraHeaders: map[string]string{
				acceptHeader: acceptApplicationJSON,
				"foo":        "bar",
				"key":        "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			header := makeAuthorizationHeader(tc.prefix, tc.token, tc.extraHeaders)
			g.Expect(header.Get("Authorization")).To(Equal(fmt.Sprintf("%s %s", tc.prefix, tc.token)))
			for k, v := range tc.extraHeaders {
				g.Expect(header.Get(k)).To(Equal(v))
			}
		})
	}
}
