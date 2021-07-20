package providers

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func TestRefresh(t *testing.T) {
	p := &ProviderData{}

	now := time.Unix(1234567890, 10)
	expires := time.Unix(1234567890, 0)

	ss := &sessions.SessionState{}
	ss.Clock.Set(now)
	ss.SetExpiresOn(expires)

	refreshed, err := p.RefreshSession(context.Background(), ss)
	assert.False(t, refreshed)
	assert.Equal(t, ErrNotImplemented, err)

	refreshed, err = p.RefreshSession(context.Background(), nil)
	assert.False(t, refreshed)
	assert.Equal(t, ErrNotImplemented, err)
}

func TestAcrValuesNotConfigured(t *testing.T) {
	p := &ProviderData{
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "my.test.idp",
			Path:   "/oauth/authorize",
		},
	}

	result := p.GetLoginURL("https://my.test.app/oauth", "", "")
	assert.NotContains(t, result, "acr_values")
}

func TestAcrValuesConfigured(t *testing.T) {
	p := &ProviderData{
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "my.test.idp",
			Path:   "/oauth/authorize",
		},
		AcrValues: "testValue",
	}

	result := p.GetLoginURL("https://my.test.app/oauth", "", "")
	assert.Contains(t, result, "acr_values=testValue")
}

func TestProviderDataEnrichSession(t *testing.T) {
	g := NewWithT(t)
	p := &ProviderData{}
	s := &sessions.SessionState{}

	err := p.EnrichSession(context.Background(), s)
	g.Expect(err).ToNot(HaveOccurred())
}

func TestProviderDataAuthorize(t *testing.T) {
	testCases := []struct {
		name          string
		allowedGroups []string
		groups        []string
		expectedAuthZ bool
	}{
		{
			name:          "NoAllowedGroups",
			allowedGroups: []string{},
			groups:        []string{},
			expectedAuthZ: true,
		},
		{
			name:          "NoAllowedGroupsUserHasGroups",
			allowedGroups: []string{},
			groups:        []string{"foo", "bar"},
			expectedAuthZ: true,
		},
		{
			name:          "UserInAllowedGroup",
			allowedGroups: []string{"foo"},
			groups:        []string{"foo", "bar"},
			expectedAuthZ: true,
		},
		{
			name:          "UserNotInAllowedGroup",
			allowedGroups: []string{"bar"},
			groups:        []string{"baz", "foo"},
			expectedAuthZ: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			session := &sessions.SessionState{
				Groups: tc.groups,
			}
			p := &ProviderData{}
			p.SetAllowedGroups(tc.allowedGroups)

			authorized, err := p.Authorize(context.Background(), session)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(authorized).To(Equal(tc.expectedAuthZ))
		})
	}
}
