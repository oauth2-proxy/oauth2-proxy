package middleware

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractGroups(t *testing.T) {
	tests := []struct {
		name        string
		claims      string
		claim       string
		want        []string
		wantInvalid bool
	}{
		{name: "default array", claims: `{"groups":["foo","bar"]}`, claim: "groups", want: []string{"foo", "bar"}},
		{name: "single string", claims: `{"groups":"foo"}`, claim: "groups", want: []string{"foo"}},
		{name: "empty array", claims: `{"groups":[]}`, claim: "groups", want: []string{}},
		{name: "null claim", claims: `{"groups":null}`, claim: "groups"},
		{name: "missing claim", claims: `{"groups":["foo"]}`, claim: "roles"},
		{name: "nested array", claims: `{"realm_access":{"roles":["foo","bar"]}}`, claim: "realm_access.roles", want: []string{"foo", "bar"}},
		{name: "nested string", claims: `{"realm_access":{"roles":"foo"}}`, claim: "realm_access.roles", want: []string{"foo"}},
		{name: "deeply nested array", claims: `{"resource_access":{"my-client":{"roles":["foo"]}}}`, claim: "resource_access.my-client.roles", want: []string{"foo"}},
		{name: "literal key takes precedence", claims: `{"realm_access.roles":["literal"],"realm_access":{"roles":["nested"]}}`, claim: "realm_access.roles", want: []string{"literal"}},
		{name: "literal null takes precedence", claims: `{"realm_access.roles":null,"realm_access":{"roles":["nested"]}}`, claim: "realm_access.roles"},
		{name: "invalid literal takes precedence", claims: `{"realm_access.roles":1,"realm_access":{"roles":["nested"]}}`, claim: "realm_access.roles", wantInvalid: true},
		{name: "missing parent", claims: `{"groups":["foo"]}`, claim: "realm_access.roles"},
		{name: "missing leaf", claims: `{"realm_access":{"other":["foo"]},"groups":["fallback"]}`, claim: "realm_access.roles"},
		{name: "null parent", claims: `{"realm_access":null}`, claim: "realm_access.roles"},
		{name: "non-object parent", claims: `{"realm_access":"foo"}`, claim: "realm_access.roles"},
		{name: "array indexing unsupported", claims: `{"realm_access":[{"roles":["foo"]}]}`, claim: "realm_access.0.roles"},
		{name: "nested empty array", claims: `{"realm_access":{"roles":[]}}`, claim: "realm_access.roles", want: []string{}},
		{name: "nested null", claims: `{"realm_access":{"roles":null}}`, claim: "realm_access.roles"},
		{name: "nested object rejected", claims: `{"realm_access":{"roles":{"name":"foo"}}}`, claim: "realm_access.roles", wantInvalid: true},
		{name: "nested mixed array rejected", claims: `{"realm_access":{"roles":["foo",1]}}`, claim: "realm_access.roles", wantInvalid: true},
		{name: "nested boolean rejected", claims: `{"realm_access":{"roles":true}}`, claim: "realm_access.roles", wantInvalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var claims map[string]json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(tt.claims), &claims))

			groups, err := extractGroups(claims, tt.claim)
			if tt.wantInvalid {
				require.EqualError(t, err, `failed to parse groups claim "`+tt.claim+`": expected a string or an array of strings`)
				require.Nil(t, groups)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, groups)
		})
	}
}
