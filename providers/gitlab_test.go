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
					Expect(err).To(MatchError(err))
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
			expectedValue []string
			projects      []string
			groups        []string
		}

		DescribeTable("should return expected results",
			func(in entitiesTableInput) {
				p.AllowUnverifiedEmail = true
				session := &sessions.SessionState{AccessToken: "gitlab_access_token"}

				err := p.AddProjects(in.projects)
				Expect(err).To(BeNil())
				p.SetProjectScope()

				if len(in.groups) > 0 {
					p.Groups = in.groups
				}

				err = p.EnrichSession(context.Background(), session)

				Expect(err).To(BeNil())
				Expect(session.Groups).To(Equal(in.expectedValue))
			},
			Entry("project membership valid on group project", entitiesTableInput{
				expectedValue: []string{"project:my_group/my_project"},
				projects:      []string{"my_group/my_project"},
			}),
			Entry("project membership invalid on group project, insufficient access level level", entitiesTableInput{
				expectedValue: nil,
				projects:      []string{"my_group/my_project=40"},
			}),
			Entry("project membership invalid on group project, no access at all", entitiesTableInput{
				expectedValue: nil,
				projects:      []string{"no_access_group/no_access_project=30"},
			}),
			Entry("project membership valid on personnal project", entitiesTableInput{
				expectedValue: []string{"project:my_profile/my_personal_project"},
				projects:      []string{"my_profile/my_personal_project"},
			}),
			Entry("project membership invalid on personnal project, insufficient access level", entitiesTableInput{
				expectedValue: nil,
				projects:      []string{"my_profile/my_personal_project=40"},
			}),
			Entry("project membership invalid", entitiesTableInput{
				expectedValue: nil,
				projects:      []string{"my_group/my_bad_project"},
			}),
			Entry("group membership valid", entitiesTableInput{
				expectedValue: []string{"group:foo"},
				groups:        []string{"foo"},
			}),
			Entry("groups and projects", entitiesTableInput{
				expectedValue: []string{"group:foo", "group:baz", "project:my_group/my_project", "project:my_profile/my_personal_project"},
				groups:        []string{"foo", "baz"},
				projects:      []string{"my_group/my_project", "my_profile/my_personal_project"},
			}),
			Entry("archived projects", entitiesTableInput{
				expectedValue: nil,
				groups:        []string{},
				projects:      []string{"my_group/my_archived_project"},
			}),
		)

	})

	Context("when generating group list from multiple kind", func() {
		type entitiesTableInput struct {
			projects []string
			groups   []string
		}

		DescribeTable("should prefix entities with group kind", func(in entitiesTableInput) {
			p.Groups = in.groups
			err := p.AddProjects(in.projects)
			Expect(err).To(BeNil())

			all := p.PrefixAllowedGroups()

			Expect(len(all)).To(Equal(len(in.projects) + len(in.groups)))
		},
			Entry("simple test case", entitiesTableInput{
				projects: []string{"my_group/my_project", "my_group/my_other_project"},
				groups:   []string{"mygroup", "myothergroup"},
			}),
			Entry("projects only", entitiesTableInput{
				projects: []string{"my_group/my_project", "my_group/my_other_project"},
				groups:   []string{},
			}),
			Entry("groups only", entitiesTableInput{
				projects: []string{},
				groups:   []string{"mygroup", "myothergroup"},
			}),
		)
	})
})
