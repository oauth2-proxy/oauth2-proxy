package providers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func testGitLabProvider(hostname string) *GitLabProvider {
	p := NewGitLabProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}

	return p
}

func testGitLabBackend() *httptest.Server {
	userInfo := `
		{
			"nickname": "FooBar",
			"email": "foo@bar.com",
			"email_verified": false,
			"groups": ["foo", "bar"]
		}
	`

	projectInfo := `
		{
			"name": "MyProject",
			"archived": false,
			"path_with_namespace": "my_group/my_project",
			"permissions": {
				"project_access": null,
				"group_access": {
					"access_level": 30,
					"notification_level": 3
				}
			}
		}
	`

	noAccessProjectInfo := `
		{
			"name": "NoAccessProject",
			"archived": false,
			"path_with_namespace": "no_access_group/no_access_project",
			"permissions": {
				"project_access": null,
				"group_access": null,
			}
		}
	`

	personalProjectInfo := `
		{
			"name": "MyPersonalProject",
			"archived": false,
			"path_with_namespace": "my_profile/my_personal_project",
			"permissions": {
				"project_access": {
					"access_level": 30,
					"notification_level": 3
				},
				"group_access": null
			}
		}
	`

	archivedProjectInfo := `
		{
			"name": "MyArchivedProject",
			"archived": true,
			"path_with_namespace": "my_group/my_archived_project",
			"permissions": {
				"project_access": {
					"access_level": 30,
					"notification_level": 3
				},
				"group_access": null
			}
		}
	`

	authHeader := "Bearer gitlab_access_token"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/oauth/userinfo":
				if r.Header["Authorization"][0] == authHeader {
					w.WriteHeader(200)
					w.Write([]byte(userInfo))
				} else {
					w.WriteHeader(401)
				}
			case "/api/v4/projects/my_group/my_project":
				if r.Header["Authorization"][0] == authHeader {
					w.WriteHeader(200)
					w.Write([]byte(projectInfo))
				} else {
					w.WriteHeader(401)
				}
			case "/api/v4/projects/no_access_group/no_access_project":
				if r.Header["Authorization"][0] == authHeader {
					w.WriteHeader(200)
					w.Write([]byte(noAccessProjectInfo))
				} else {
					w.WriteHeader(401)
				}
			case "/api/v4/projects/my_group/my_archived_project":
				if r.Header["Authorization"][0] == authHeader {
					w.WriteHeader(200)
					w.Write([]byte(archivedProjectInfo))
				} else {
					w.WriteHeader(401)
				}
			case "/api/v4/projects/my_profile/my_personal_project":
				if r.Header["Authorization"][0] == authHeader {
					w.WriteHeader(200)
					w.Write([]byte(personalProjectInfo))
				} else {
					w.WriteHeader(401)
				}
			case "/api/v4/projects/my_group/my_bad_project":
				w.WriteHeader(403)
			default:
				w.WriteHeader(404)
			}
		}))
}

var _ = Describe("Gitlab Provider Tests", func() {
	var p *GitLabProvider
	var b *httptest.Server

	BeforeEach(func() {
		b = testGitLabBackend()

		bURL, err := url.Parse(b.URL)
		Expect(err).To(BeNil())

		p = testGitLabProvider(bURL.Host)
	})

	AfterEach(func() {
		b.Close()
	})

	Context("with bad token", func() {
		It("should trigger an error", func() {
			p.AllowUnverifiedEmail = false
			session := &sessions.SessionState{AccessToken: "unexpected_gitlab_access_token"}
			err := p.EnrichSession(context.Background(), session)
			Expect(err).To(MatchError(errors.New("failed to retrieve user info: error getting user info: unexpected status \"401\": ")))
		})
	})

	Context("when filtering on email", func() {
		type emailsTableInput struct {
			expectedError        error
			expectedValue        string
			allowUnverifiedEmail bool
		}

		DescribeTable("should return expected results",
			func(in emailsTableInput) {
				p.AllowUnverifiedEmail = in.allowUnverifiedEmail
				session := &sessions.SessionState{AccessToken: "gitlab_access_token"}

				err := p.EnrichSession(context.Background(), session)

				if in.expectedError != nil {
					Expect(err).To(MatchError(in.expectedError))
				} else {
					Expect(err).To(BeNil())
					Expect(session.Email).To(Equal(in.expectedValue))
				}
			},
			Entry("unverified email denied", emailsTableInput{
				expectedError:        errors.New("user email is not verified"),
				allowUnverifiedEmail: false,
			}),
			Entry("unverified email allowed", emailsTableInput{
				expectedError:        nil,
				expectedValue:        "foo@bar.com",
				allowUnverifiedEmail: true,
			}),
		)
	})

	Context("when filtering on gitlab entities (groups and projects)", func() {
		type entitiesTableInput struct {
			allowedProjects []string
			allowedGroups   []string
			scope           string
			expectedAuthz   bool
			expectedError   error
			expectedGroups  []string
			expectedScope   string
		}

		DescribeTable("should return expected results",
			func(in entitiesTableInput) {
				p.AllowUnverifiedEmail = true
				if in.scope != "" {
					p.Scope = in.scope
				}
				session := &sessions.SessionState{AccessToken: "gitlab_access_token"}

				p.SetAllowedGroups(in.allowedGroups)

				err := p.SetAllowedProjects(in.allowedProjects)
				if in.expectedError == nil {
					Expect(err).To(BeNil())
				} else {
					Expect(err).To(MatchError(in.expectedError))
					return
				}
				Expect(p.Scope).To(Equal(in.expectedScope))

				err = p.EnrichSession(context.Background(), session)
				Expect(err).To(BeNil())
				Expect(session.Groups).To(Equal(in.expectedGroups))

				authorized, err := p.Authorize(context.Background(), session)
				Expect(err).To(BeNil())
				Expect(authorized).To(Equal(in.expectedAuthz))
			},
			Entry("project membership valid on group project", entitiesTableInput{
				allowedProjects: []string{"my_group/my_project"},
				expectedAuthz:   true,
				expectedGroups:  []string{"foo", "bar", "project:my_group/my_project"},
				expectedScope:   "openid email read_api",
			}),
			Entry("project membership invalid on group project, insufficient access level level", entitiesTableInput{
				allowedProjects: []string{"my_group/my_project=40"},
				expectedAuthz:   false,
				expectedGroups:  []string{"foo", "bar"},
				expectedScope:   "openid email read_api",
			}),
			Entry("project membership invalid on group project, no access at all", entitiesTableInput{
				allowedProjects: []string{"no_access_group/no_access_project=30"},
				expectedAuthz:   false,
				expectedGroups:  []string{"foo", "bar"},
				expectedScope:   "openid email read_api",
			}),
			Entry("project membership valid on personnal project", entitiesTableInput{
				allowedProjects: []string{"my_profile/my_personal_project"},
				scope:           "openid email read_api profile",
				expectedAuthz:   true,
				expectedGroups:  []string{"foo", "bar", "project:my_profile/my_personal_project"},
				expectedScope:   "openid email read_api profile",
			}),
			Entry("project membership invalid on personnal project, insufficient access level", entitiesTableInput{
				allowedProjects: []string{"my_profile/my_personal_project=40"},
				expectedAuthz:   false,
				expectedGroups:  []string{"foo", "bar"},
				expectedScope:   "openid email read_api",
			}),
			Entry("project membership invalid", entitiesTableInput{
				allowedProjects: []string{"my_group/my_bad_project"},
				expectedAuthz:   false,
				expectedGroups:  []string{"foo", "bar"},
				expectedScope:   "openid email read_api",
			}),
			Entry("group membership valid", entitiesTableInput{
				allowedGroups:  []string{"foo"},
				expectedGroups: []string{"foo", "bar"},
				expectedAuthz:  true,
				expectedScope:  "openid email",
			}),
			Entry("groups and projects", entitiesTableInput{
				allowedGroups:   []string{"foo", "baz"},
				allowedProjects: []string{"my_group/my_project", "my_profile/my_personal_project"},
				expectedAuthz:   true,
				expectedGroups:  []string{"foo", "bar", "project:my_group/my_project", "project:my_profile/my_personal_project"},
				expectedScope:   "openid email read_api",
			}),
			Entry("archived projects", entitiesTableInput{
				allowedProjects: []string{"my_group/my_archived_project"},
				expectedAuthz:   false,
				expectedGroups:  []string{"foo", "bar"},
				expectedScope:   "openid email read_api",
			}),
			Entry("invalid project format", entitiesTableInput{
				allowedProjects: []string{"my_group/my_invalid_project=123"},
				expectedError:   errors.New("invalid gitlab project access level specified (my_group/my_invalid_project)"),
				expectedScope:   "openid email read_api",
			}),
		)
	})
})
