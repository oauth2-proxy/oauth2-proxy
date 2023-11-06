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

func TestCodeChallengeConfigured(t *testing.T) {
	p := &ProviderData{
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "my.test.idp",
			Path:   "/oauth/authorize",
		},
	}

	extraValues := url.Values{}
	extraValues["code_challenge"] = []string{"challenge"}
	extraValues["code_challenge_method"] = []string{"method"}
	result := p.GetLoginURL("https://my.test.app/oauth", "", "", extraValues)
	assert.Contains(t, result, "code_challenge=challenge")
	assert.Contains(t, result, "code_challenge_method=method")
}

func TestCodeChallengeNotConfigured(t *testing.T) {
	p := &ProviderData{
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "my.test.idp",
			Path:   "/oauth/authorize",
		},
	}

	result := p.GetLoginURL("https://my.test.app/oauth", "", "", url.Values{})
	assert.NotContains(t, result, "code_challenge")
	assert.NotContains(t, result, "code_challenge_method")
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
		now           time.Time
		expires       time.Time
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
		{
			name:          "SessionExpired",
			now:           time.Unix(1234567890, 0),
			expires:       time.Unix(1234567889, 0),
			expectedAuthZ: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			session := &sessions.SessionState{
				Groups: tc.groups,
			}
			session.Clock.Set(tc.now)
			session.SetExpiresOn(tc.expires)
			p := &ProviderData{}
			p.setAllowedGroups(tc.allowedGroups)

			authorized, err := p.Authorize(context.Background(), session)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(authorized).To(Equal(tc.expectedAuthZ))
		})
	}
}
