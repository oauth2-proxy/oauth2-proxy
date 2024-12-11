package util

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	emptyJSON             = "{}"
	profilePath           = "/userinfo"
	authorizedAccessToken = "valid_access_token"
	basicIDTokenPayload   = `{
      "user": "idTokenUser",
      "email": "idTokenEmail",
      "groups": [
        "idTokenGroup1",
        "idTokenGroup2"
      ],
	  "nested-groups-claim-containing-hyphen": {
			"groups": [
				"nestedClaimContainingHypenGroup1",
				"nestedClaimContainingHypenGroup2"
			]
	  },
      "https://groups.test": [
        "fqdnGroup1",
        "fqdnGroup2"
      ]
    }`
	basicProfileURLPayload = `{
        "user": "profileUser",
        "email": "profileEmail",
        "groups": [
          "profileGroup1",
          "profileGroup2"
        ]
      }`
	nestedClaimPayload = `{
      "auth": {
        "user": {
          "username": "nestedUser"
        }
      }
    }`
	complexGroupsPayload = `{
      "groups": [
        {
          "groupID": "group1",
          "roles": ["admin"]
        },
        {
          "groupID": "group2",
          "roles": ["user", "employee"]
        }
      ]
    }`
)

var _ = Describe("Claim Extractor Suite", func() {
	Context("Claim Extractor", func() {
		type newClaimExtractorTableInput struct {
			idToken       string
			expectedError error
		}

		DescribeTable("NewClaimExtractor",
			func(in newClaimExtractorTableInput) {
				_, err := NewClaimExtractor(context.Background(), in.idToken, nil, nil)
				if in.expectedError != nil {
					Expect(err).To(MatchError(in.expectedError))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
			},
			Entry("with a valid JWT", newClaimExtractorTableInput{
				idToken:       createJWTFromPayload(basicIDTokenPayload),
				expectedError: nil,
			}),
			Entry("with a JWT with a non-json payload", newClaimExtractorTableInput{
				idToken:       createJWTFromPayload("this is not JSON"),
				expectedError: errors.New("failed to parse ID Token payload: invalid character 'h' in literal true (expecting 'r')"),
			}),
			Entry("with an IDToken with the wrong number of parts", newClaimExtractorTableInput{
				idToken:       "eyJeyJ",
				expectedError: errors.New("failed to parse ID Token: oidc: malformed jwt, expected 3 parts got 1"),
			}),
			Entry("with an non-base64 IDToken", newClaimExtractorTableInput{
				idToken:       "{metadata}.{payload}.{signature}",
				expectedError: errors.New("failed to parse ID Token: oidc: malformed jwt payload: illegal base64 data at input byte 0"),
			}),
		)

		type getClaimTableInput struct {
			testClaimExtractorOpts
			claim         string
			expectedValue interface{}
			expectExists  bool
			expectedError error
		}

		DescribeTable("GetClaim",
			func(in getClaimTableInput) {
				claimExtractor, serverClose, err := newTestClaimExtractor(in.testClaimExtractorOpts)
				Expect(err).ToNot(HaveOccurred())
				if serverClose != nil {
					defer serverClose()
				}

				value, exists, err := claimExtractor.GetClaim(in.claim)
				if in.expectedError != nil {
					Expect(err).To(MatchError(in.expectedError))
					return
				}

				Expect(err).ToNot(HaveOccurred())
				if in.expectedValue != nil {
					Expect(value).To(Equal(in.expectedValue))
				} else {
					Expect(value).To(BeNil())
				}

				Expect(exists).To(Equal(in.expectExists))
			},
			Entry("retrieves a string claim from ID Token when present", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload:        basicIDTokenPayload,
					setProfileURL:         true,
					profileRequestHeaders: newAuthorizedHeader(),
					profileRequestHandler: shouldNotBeRequestedProfileHandler,
				},
				claim:         "user",
				expectExists:  true,
				expectedValue: "idTokenUser",
				expectedError: nil,
			}),
			Entry("retrieves a slice claim from ID Token when present", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload:        basicIDTokenPayload,
					setProfileURL:         true,
					profileRequestHeaders: newAuthorizedHeader(),
					profileRequestHandler: shouldNotBeRequestedProfileHandler,
				},
				claim:         "groups",
				expectExists:  true,
				expectedValue: []interface{}{"idTokenGroup1", "idTokenGroup2"},
				expectedError: nil,
			}),
			Entry("when the requested claim is the empty string", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload: basicIDTokenPayload,
				},
				claim:         "",
				expectExists:  false,
				expectedValue: nil,
				expectedError: nil,
			}),
			Entry("when the requested claim is the not found (with no profile URL)", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload:        basicIDTokenPayload,
					profileRequestHeaders: newAuthorizedHeader(),
				},
				claim:         "not_found",
				expectExists:  false,
				expectedValue: nil,
				expectedError: nil,
			}),
			Entry("when the requested claim is the not found (with profile URL)", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload:        basicIDTokenPayload,
					setProfileURL:         true,
					profileRequestHeaders: newAuthorizedHeader(),
					profileRequestHandler: requiresAuthProfileHandler,
				},
				claim:         "not_found",
				expectExists:  false,
				expectedValue: nil,
				expectedError: nil,
			}),
			Entry("when the requested claim is the not found (with no profile Headers)", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload:        basicIDTokenPayload,
					setProfileURL:         true,
					profileRequestHeaders: nil,
					profileRequestHandler: shouldNotBeRequestedProfileHandler,
				},
				claim:         "not_found",
				expectExists:  false,
				expectedValue: nil,
				expectedError: nil,
			}),
			Entry("when the profile URL is unauthorized", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload:        emptyJSON,
					setProfileURL:         true,
					profileRequestHeaders: make(http.Header),
					profileRequestHandler: requiresAuthProfileHandler,
				},
				claim:         "user",
				expectExists:  false,
				expectedValue: nil,
				expectedError: errors.New("failed to fetch claims from profile URL: error making request to profile URL: unexpected status \"403\": Unauthorized"),
			}),
			Entry("retrieves a string claim from profile URL when not present in the ID Token", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload:        emptyJSON,
					setProfileURL:         true,
					profileRequestHeaders: newAuthorizedHeader(),
					profileRequestHandler: requiresAuthProfileHandler,
				},
				claim:         "user",
				expectExists:  true,
				expectedValue: "profileUser",
				expectedError: nil,
			}),
			Entry("retrieves a string claim from a nested path", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload:        nestedClaimPayload,
					setProfileURL:         true,
					profileRequestHeaders: newAuthorizedHeader(),
					profileRequestHandler: shouldNotBeRequestedProfileHandler,
				},
				claim:         "auth.user.username",
				expectExists:  true,
				expectedValue: "nestedUser",
				expectedError: nil,
			}),
			Entry("retrieves claim for with FQDN", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload:        basicIDTokenPayload,
					setProfileURL:         true,
					profileRequestHeaders: newAuthorizedHeader(),
					profileRequestHandler: shouldNotBeRequestedProfileHandler,
				},
				claim:         "https://groups.test",
				expectExists:  true,
				expectedValue: []interface{}{"fqdnGroup1", "fqdnGroup2"},
				expectedError: nil,
			}),
			Entry("retrieves claim with nested groups claim containing hyphen", getClaimTableInput{
				testClaimExtractorOpts: testClaimExtractorOpts{
					idTokenPayload:        basicIDTokenPayload,
					setProfileURL:         true,
					profileRequestHeaders: newAuthorizedHeader(),
					profileRequestHandler: shouldNotBeRequestedProfileHandler,
				},
				claim:         "nested-groups-claim-containing-hyphen.groups",
				expectExists:  true,
				expectedValue: []interface{}{"nestedClaimContainingHypenGroup1", "nestedClaimContainingHypenGroup2"},
				expectedError: nil,
			}),
		)
	})

	It("GetClaim should only call the profile URL once", func() {
		var counter int32
		countRequestsHandler := func(rw http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&counter, 1)
			rw.Write([]byte(basicProfileURLPayload))
		}

		claimExtractor, serverClose, err := newTestClaimExtractor(testClaimExtractorOpts{
			idTokenPayload:        "{}",
			setProfileURL:         true,
			profileRequestHeaders: newAuthorizedHeader(),
			profileRequestHandler: countRequestsHandler,
		})
		Expect(err).ToNot(HaveOccurred())
		if serverClose != nil {
			defer serverClose()
		}

		value, exists, err := claimExtractor.GetClaim("user")
		Expect(err).ToNot(HaveOccurred())
		Expect(exists).To(BeTrue())
		Expect(value).To(Equal("profileUser"))
		Expect(counter).To(BeEquivalentTo(1))

		// Check a different claim, but expect the count not to increase
		value, exists, err = claimExtractor.GetClaim("email")
		Expect(err).ToNot(HaveOccurred())
		Expect(exists).To(BeTrue())
		Expect(value).To(Equal("profileEmail"))
		Expect(counter).To(BeEquivalentTo(1))
	})

	It("GetClaim should not return an error with a non-nil empty ProfileURL", func() {
		claims, serverClose, err := newTestClaimExtractor(testClaimExtractorOpts{
			idTokenPayload:        "{}",
			profileRequestHeaders: newAuthorizedHeader(),
		})
		Expect(err).ToNot(HaveOccurred())
		if serverClose != nil {
			defer serverClose()
		}
		// Set the ProfileURL to be empty, but not nil
		claims.(*claimExtractor).profileURL = &url.URL{}

		value, exists, err := claims.GetClaim("user")
		Expect(err).ToNot(HaveOccurred())
		Expect(exists).To(BeFalse())
		Expect(value).To(BeNil())
	})

	type getClaimIntoTableInput struct {
		testClaimExtractorOpts
		into          interface{}
		claim         string
		expectedValue interface{}
		expectExists  bool
		expectedError error
	}

	DescribeTable("GetClaimInto",
		func(in getClaimIntoTableInput) {
			claimExtractor, serverClose, err := newTestClaimExtractor(in.testClaimExtractorOpts)
			Expect(err).ToNot(HaveOccurred())
			if serverClose != nil {
				defer serverClose()
			}

			exists, err := claimExtractor.GetClaimInto(in.claim, in.into)
			if in.expectedError != nil {
				Expect(err).To(MatchError(in.expectedError))
				return
			}

			Expect(err).ToNot(HaveOccurred())
			if in.expectedValue != nil {
				Expect(in.into).To(Equal(in.expectedValue))
			} else {
				Expect(in.into).To(BeEmpty())
			}

			Expect(exists).To(Equal(in.expectExists))
		},
		Entry("retrieves a string claim from ID Token when present into a string", getClaimIntoTableInput{
			testClaimExtractorOpts: testClaimExtractorOpts{
				idTokenPayload:        basicIDTokenPayload,
				setProfileURL:         true,
				profileRequestHeaders: newAuthorizedHeader(),
				profileRequestHandler: shouldNotBeRequestedProfileHandler,
			},
			claim:         "user",
			into:          stringPointer(""),
			expectExists:  true,
			expectedValue: stringPointer("idTokenUser"),
			expectedError: nil,
		}),
		Entry("retrieves a string claim from ID Token when present into a string slice", getClaimIntoTableInput{
			testClaimExtractorOpts: testClaimExtractorOpts{
				idTokenPayload:        basicIDTokenPayload,
				setProfileURL:         true,
				profileRequestHeaders: newAuthorizedHeader(),
				profileRequestHandler: shouldNotBeRequestedProfileHandler,
			},
			claim:         "user",
			into:          stringSlicePointer([]string{}),
			expectExists:  true,
			expectedValue: stringSlicePointer([]string{"idTokenUser"}),
			expectedError: nil,
		}),
		Entry("retrieves a string slice claim from ID Token when present into a string slice", getClaimIntoTableInput{
			testClaimExtractorOpts: testClaimExtractorOpts{
				idTokenPayload:        basicIDTokenPayload,
				setProfileURL:         true,
				profileRequestHeaders: newAuthorizedHeader(),
				profileRequestHandler: shouldNotBeRequestedProfileHandler,
			},
			claim:         "groups",
			into:          stringSlicePointer([]string{}),
			expectExists:  true,
			expectedValue: stringSlicePointer([]string{"idTokenGroup1", "idTokenGroup2"}),
			expectedError: nil,
		}),
		Entry("retrieves a string slice claim from ID Token when present into a string", getClaimIntoTableInput{
			testClaimExtractorOpts: testClaimExtractorOpts{
				idTokenPayload:        basicIDTokenPayload,
				setProfileURL:         true,
				profileRequestHeaders: newAuthorizedHeader(),
				profileRequestHandler: shouldNotBeRequestedProfileHandler,
			},
			claim:         "groups",
			into:          stringPointer(""),
			expectExists:  true,
			expectedValue: stringPointer("[\"idTokenGroup1\",\"idTokenGroup2\"]"),
			expectedError: nil,
		}),
		Entry("returns an error when a non-pointer is passed for the destination", getClaimIntoTableInput{
			testClaimExtractorOpts: testClaimExtractorOpts{
				idTokenPayload:        basicIDTokenPayload,
				setProfileURL:         true,
				profileRequestHeaders: newAuthorizedHeader(),
				profileRequestHandler: shouldNotBeRequestedProfileHandler,
			},
			claim:         "user",
			into:          "",
			expectExists:  false,
			expectedValue: "",
			expectedError: errors.New("could no coerce claim: unknown type for destination: string"),
		}),
		Entry("flattens a complex claim value into a JSON string", getClaimIntoTableInput{
			testClaimExtractorOpts: testClaimExtractorOpts{
				idTokenPayload:        complexGroupsPayload,
				setProfileURL:         true,
				profileRequestHeaders: newAuthorizedHeader(),
				profileRequestHandler: shouldNotBeRequestedProfileHandler,
			},
			claim:        "groups",
			into:         stringSlicePointer([]string{}),
			expectExists: true,
			expectedValue: stringSlicePointer([]string{
				"{\"groupID\":\"group1\",\"roles\":[\"admin\"]}",
				"{\"groupID\":\"group2\",\"roles\":[\"user\",\"employee\"]}",
			}),
			expectedError: nil,
		}),
		Entry("does not return an error when the claim does not exist", getClaimIntoTableInput{
			testClaimExtractorOpts: testClaimExtractorOpts{
				idTokenPayload:        basicIDTokenPayload,
				setProfileURL:         true,
				profileRequestHeaders: newAuthorizedHeader(),
				profileRequestHandler: requiresAuthProfileHandler,
			},
			claim:         "not_found",
			into:          stringPointer(""),
			expectExists:  false,
			expectedValue: stringPointer(""),
			expectedError: nil,
		}),
		Entry("returns an error when the profile request is unauthorized", getClaimIntoTableInput{
			testClaimExtractorOpts: testClaimExtractorOpts{
				idTokenPayload:        emptyJSON,
				setProfileURL:         true,
				profileRequestHeaders: make(http.Header),
				profileRequestHandler: requiresAuthProfileHandler,
			},
			claim:         "user",
			into:          stringPointer(""),
			expectExists:  false,
			expectedValue: stringPointer(""),
			expectedError: errors.New("could not get claim \"user\": failed to fetch claims from profile URL: error making request to profile URL: unexpected status \"403\": Unauthorized"),
		}),
	)

	type coerceClaimTableInput struct {
		value         interface{}
		dst           interface{}
		expectedDst   interface{}
		expectedError error
	}

	DescribeTable("coerceClaim",
		func(in coerceClaimTableInput) {
			err := coerceClaim(in.value, in.dst)
			if in.expectedError != nil {
				Expect(err).To(MatchError(in.expectedError))
				return
			}

			Expect(err).ToNot(HaveOccurred())
			Expect(in.dst).To(Equal(in.expectedDst))
		},
		Entry("coerces a string to a string", coerceClaimTableInput{
			value:       "some_string",
			dst:         stringPointer(""),
			expectedDst: stringPointer("some_string"),
		}),
		Entry("coerces a slice to a string slice", coerceClaimTableInput{
			value:       []interface{}{"a", "b"},
			dst:         stringSlicePointer([]string{}),
			expectedDst: stringSlicePointer([]string{"a", "b"}),
		}),
		Entry("coerces a bool to a bool", coerceClaimTableInput{
			value:       true,
			dst:         boolPointer(false),
			expectedDst: boolPointer(true),
		}),
		Entry("coerces a string to a bool", coerceClaimTableInput{
			value:       "true",
			dst:         boolPointer(false),
			expectedDst: boolPointer(true),
		}),
		Entry("coerces a map to a string", coerceClaimTableInput{
			value: map[string]interface{}{
				"foo": []interface{}{"bar", "baz"},
			},
			dst:         stringPointer(""),
			expectedDst: stringPointer("{\"foo\":[\"bar\",\"baz\"]}"),
		}),
	)
})

// ******************************************
// Helpers for setting up the claim extractor
// ******************************************

type testClaimExtractorOpts struct {
	idTokenPayload        string
	setProfileURL         bool
	profileRequestHeaders http.Header
	profileRequestHandler http.HandlerFunc
}

func newTestClaimExtractor(in testClaimExtractorOpts) (ClaimExtractor, func(), error) {
	var profileURL *url.URL
	var closeServer func()
	if in.setProfileURL {
		server := httptest.NewServer(http.HandlerFunc(in.profileRequestHandler))
		closeServer = server.Close

		var err error
		profileURL, err = url.Parse("http://" + server.Listener.Addr().String() + profilePath)
		Expect(err).ToNot(HaveOccurred())
	}

	rawIDToken := createJWTFromPayload(in.idTokenPayload)

	claimExtractor, err := NewClaimExtractor(context.Background(), rawIDToken, profileURL, in.profileRequestHeaders)
	return claimExtractor, closeServer, err
}

func createJWTFromPayload(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(emptyJSON))
	payloadJSON := base64.RawURLEncoding.EncodeToString([]byte(payload))

	return fmt.Sprintf("%s.%s.%s", header, payloadJSON, header)
}

func newAuthorizedHeader() http.Header {
	headers := make(http.Header)
	headers.Add("Authorization", "Bearer "+authorizedAccessToken)
	return headers
}

func hasAuthorizedHeader(headers http.Header) bool {
	return headers.Get("Authorization") == "Bearer "+authorizedAccessToken
}

// ***********************
// Typed Pointer Functions
// ***********************

func stringPointer(in string) *string {
	return &in
}

func stringSlicePointer(in []string) *[]string {
	return &in
}

func boolPointer(in bool) *bool {
	return &in
}

// ******************************
// Different profile URL handlers
// ******************************

func shouldNotBeRequestedProfileHandler(_ http.ResponseWriter, _ *http.Request) {
	defer GinkgoRecover()
	Expect(true).To(BeFalse(), "Unexpected request to profile URL")
}

func requiresAuthProfileHandler(rw http.ResponseWriter, req *http.Request) {
	if !hasAuthorizedHeader(req.Header) {
		rw.WriteHeader(403)
		rw.Write([]byte("Unauthorized"))
		return
	}

	rw.Write([]byte(basicProfileURLPayload))
}
