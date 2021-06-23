package main

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
)

type ValidatorTest struct {
	authEmailFileName string
	done              chan bool
	updateSeen        bool
}

func NewValidatorTest(t *testing.T) *ValidatorTest {
	vt := &ValidatorTest{}
	var err error
	f, err := ioutil.TempFile("", "test_auth_emails_")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	vt.authEmailFileName = f.Name()
	vt.done = make(chan bool, 1)
	return vt
}

func (vt *ValidatorTest) TearDown() {
	vt.done <- true
	os.Remove(vt.authEmailFileName)
}

func (vt *ValidatorTest) NewValidator(domains []string,
	updated chan<- bool) func(string) bool {
	return newValidatorImpl(domains, vt.authEmailFileName,
		vt.done, func() {
			if vt.updateSeen == false {
				updated <- true
				vt.updateSeen = true
			}
		})
}

func (vt *ValidatorTest) WriteEmails(t *testing.T, emails []string) {
	f, err := os.OpenFile(vt.authEmailFileName, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("failed to open auth email file: %v", err)
	}

	if _, err := f.WriteString(strings.Join(emails, "\n")); err != nil {
		t.Fatalf("failed to write emails to auth email file: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("failed to close auth email file: %v", err)
	}
}

func TestValidatorOverwriteEmailListDirectly(t *testing.T) {
	testCasesPreUpdate := []struct {
		name          string
		email         string
		expectedAuthZ bool
	}{
		{
			name:          "FirstEmailInList",
			email:         "xyzzy@example.com",
			expectedAuthZ: true,
		},
		{
			name:          "SecondEmailInList",
			email:         "plugh@example.com",
			expectedAuthZ: true,
		},
		{
			name:          "EmailNotInListThatMatchesNoDomains",
			email:         "xyzzy.plugh@example.com",
			expectedAuthZ: false,
		},
	}
	testCasesPostUpdate := []struct {
		name          string
		email         string
		expectedAuthZ bool
	}{
		{
			name:          "email removed from list",
			email:         "xyzzy@example.com",
			expectedAuthZ: false,
		},
		{
			name:          "email retained in list",
			email:         "plugh@example.com",
			expectedAuthZ: true,
		},
		{
			name:          "email added to list",
			email:         "xyzzy.plugh@example.com",
			expectedAuthZ: true,
		},
	}

	vt := NewValidatorTest(t)
	defer vt.TearDown()

	vt.WriteEmails(t, []string{
		"xyzzy@example.com",
		"plugh@example.com",
	})
	updated := make(chan bool)
	validator := vt.NewValidator([]string(nil), updated)

	for _, tc := range testCasesPreUpdate {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			authorized := validator(tc.email)
			g.Expect(authorized).To(Equal(tc.expectedAuthZ))
		})
	}

	vt.WriteEmails(t, []string{
		"xyzzy.plugh@example.com",
		"plugh@example.com",
	})
	<-updated

	for _, tc := range testCasesPostUpdate {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			authorized := validator(tc.email)
			g.Expect(authorized).To(Equal(tc.expectedAuthZ))
		})
	}
}

func TestValidatorCases(t *testing.T) {
	testCases := []struct {
		name           string
		allowedEmails  []string
		allowedDomains []string
		email          string
		expectedAuthZ  bool
	}{
		{
			name:           "EmailNotInCorrect1stSubDomainsNotInEmails",
			allowedEmails:  []string{"xyzzy@example.com", "plugh@example.com"},
			allowedDomains: []string{".example0.com", ".example1.com"},
			email:          "foo.bar@example0.com",
			expectedAuthZ:  false,
		},
		{
			name:           "EmailInFirstDomain",
			allowedEmails:  []string{"xyzzy@example.com", "plugh@example.com"},
			allowedDomains: []string{".example0.com", ".example1.com"},
			email:          "foo@bar.example0.com",
			expectedAuthZ:  true,
		},
		{
			name:           "EmailNotInCorrect2ndSubDomainsNotInEmails",
			allowedEmails:  []string{"xyzzy@example.com", "plugh@example.com"},
			allowedDomains: []string{".example0.com", ".example1.com"},
			email:          "baz.quux@example1.com",
			expectedAuthZ:  false,
		},
		{
			name:           "EmailInSecondDomain",
			allowedEmails:  []string{"xyzzy@example.com", "plugh@example.com"},
			allowedDomains: []string{".example0.com", ".example1.com"},
			email:          "baz@quux.example1.com",
			expectedAuthZ:  true,
		},
		{
			name:           "EmailInFirstEmailList",
			allowedEmails:  []string{"xyzzy@example.com", "plugh@example.com"},
			allowedDomains: []string{".example0.com", ".example1.com"},
			email:          "xyzzy@example.com",
			expectedAuthZ:  true,
		},
		{
			name:           "EmailNotInDomainsNotInEmails",
			allowedEmails:  []string{"xyzzy@example.com", "plugh@example.com"},
			allowedDomains: []string{".example0.com", ".example1.com"},
			email:          "xyzzy.plugh@example.com",
			expectedAuthZ:  false,
		},
		{
			name:           "EmailInLastEmailList",
			allowedEmails:  []string{"xyzzy@example.com", "plugh@example.com"},
			allowedDomains: []string{".example0.com", ".example1.com"},
			email:          "plugh@example.com",
			expectedAuthZ:  true,
		},
		{
			name:           "EmailIn1stSubdomain",
			allowedEmails:  nil,
			allowedDomains: []string{"us.example.com", "de.example.com", "example.com"},
			email:          "xyzzy@us.example.com",
			expectedAuthZ:  true,
		},
		{
			name:           "EmailIn2ndSubdomain",
			allowedEmails:  nil,
			allowedDomains: []string{"us.example.com", "de.example.com", "example.com"},
			email:          "xyzzy@de.example.com",
			expectedAuthZ:  true,
		},
		{
			name:           "EmailNotInAnySubdomain",
			allowedEmails:  nil,
			allowedDomains: []string{"us.example.com", "de.example.com", "example.com"},
			email:          "global@au.example.com",
			expectedAuthZ:  false,
		},
		{
			name:           "EmailInLastSubdomain",
			allowedEmails:  nil,
			allowedDomains: []string{"us.example.com", "de.example.com", "example.com"},
			email:          "xyzzy@example.com",
			expectedAuthZ:  true,
		},
		{
			name:           "EmailDomainNotCompletelyMatch",
			allowedEmails:  nil,
			allowedDomains: []string{".example.com", ".example1.com"},
			email:          "something@fooexample.com",
			expectedAuthZ:  false,
		},
		{
			name:           "HackerExtraDomainPrefix1",
			allowedEmails:  nil,
			allowedDomains: []string{".mycompany.com"},
			email:          "something@evilhackmycompany.com",
			expectedAuthZ:  false,
		},
		{
			name:           "HackerExtraDomainPrefix2",
			allowedEmails:  nil,
			allowedDomains: []string{".mycompany.com"},
			email:          "something@ext.evilhackmycompany.com",
			expectedAuthZ:  false,
		},
		{
			name:           "EmptyDomainAndEmailList",
			allowedEmails:  []string(nil),
			allowedDomains: []string(nil),
			email:          "foo.bar@example.com",
			expectedAuthZ:  false,
		},
		{
			name:           "EmailMatchWithAllowedEmails",
			email:          "foo.bar@example.com",
			allowedEmails:  []string{"foo.bar@example.com"},
			allowedDomains: []string{"example.com"},
			expectedAuthZ:  true,
		},
		{
			name:           "EmailFromSameDomainButNotInList",
			email:          "baz.quux@example.com",
			allowedEmails:  []string{"foo.bar@example.com"},
			allowedDomains: []string(nil),
			expectedAuthZ:  false,
		},
		{
			name:           "EmailMatchOnDomain",
			email:          "foo.bar@example.com",
			allowedEmails:  []string(nil),
			allowedDomains: []string{"example.com"},
			expectedAuthZ:  true,
		},
		{
			name:           "EmailMatchOnDomain2",
			email:          "baz.quux@example.com",
			allowedEmails:  []string(nil),
			allowedDomains: []string{"example.com"},
			expectedAuthZ:  true,
		},
		{
			name:           "EmailFromFirstDomainShouldValidate",
			email:          "foo.bar@example0.com",
			allowedEmails:  []string{"Foo.Bar@Example.Com"},
			allowedDomains: []string{"example0.com", "example1.com"},
			expectedAuthZ:  true,
		},
		{
			name:           "EmailFromSecondDomainShouldValidate",
			email:          "baz.quux@example1.com",
			allowedEmails:  []string{"Foo.Bar@Example.Com"},
			allowedDomains: []string{"example0.com", "example1.com"},
			expectedAuthZ:  true,
		},
		{
			name:           "FirstEmailInListShouldValidate",
			email:          "xyzzy@example.com",
			allowedEmails:  []string{"xyzzy@example.com", "plugh@example.com"},
			allowedDomains: []string{"example0.com", "example1.com"},
			expectedAuthZ:  true,
		},
		{
			name:           "SecondEmailInListShouldValidate",
			email:          "plugh@example.com",
			allowedEmails:  []string{"xyzzy@example.com", "plugh@example.com"},
			allowedDomains: []string{"example0.com", "example1.com"},
			expectedAuthZ:  true,
		},
		{
			name:           "EmailNotInListThatMatchesNoDomains ",
			email:          "xyzzy.plugh@example.com",
			allowedEmails:  []string{"xyzzy@example.com", "plugh@example.com"},
			allowedDomains: []string{"example0.com", "example1.com"},
			expectedAuthZ:  false,
		},
		{
			name:           "LoadedEmailAddressesAreNotLowerCased",
			email:          "foo.bar@example.com",
			allowedEmails:  []string{"Foo.Bar@Example.Com"},
			allowedDomains: []string{"Frobozz.Com"},
			expectedAuthZ:  true,
		},
		{
			name:           "ValidatedEmailAddressesAreNotLowerCased",
			email:          "Foo.Bar@Example.Com",
			allowedEmails:  []string{"Foo.Bar@Example.Com"},
			allowedDomains: []string{"Frobozz.Com"},
			expectedAuthZ:  true,
		},
		{
			name:           "LoadedDomainsAreNotLowerCased",
			email:          "foo.bar@frobozz.com",
			allowedEmails:  []string{"Foo.Bar@Example.Com"},
			allowedDomains: []string{"Frobozz.Com"},
			expectedAuthZ:  true,
		},
		{
			name:           "ValidatedDomainsAreNotLowerCased",
			email:          "foo.bar@Frobozz.Com",
			allowedEmails:  []string{"Foo.Bar@Example.Com"},
			allowedDomains: []string{"Frobozz.Com"},
			expectedAuthZ:  true,
		},
		{
			name:           "IgnoreSpacesInAuthEmails",
			email:          "foo.bar@example.com",
			allowedEmails:  []string{"   foo.bar@example.com   "},
			allowedDomains: []string(nil),
			expectedAuthZ:  true,
		},
		{
			name:           "IgnorePrefixSpacesInAuthEmails",
			email:          "foo.bar@example.com",
			allowedEmails:  []string{"   foo.bar@example.com"},
			allowedDomains: []string(nil),
			expectedAuthZ:  true,
		},
		{
			name:           "CheckForEqualityNotSuffix",
			email:          "foo@evilcompany.com",
			allowedEmails:  []string(nil),
			allowedDomains: []string{".company.com"},
			expectedAuthZ:  false,
		},
		{
			name:           "CheckForEqualityNotSuffix2",
			email:          "foo@evilcompany.com",
			allowedEmails:  []string(nil),
			allowedDomains: []string{"company.com"},
			expectedAuthZ:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vt := NewValidatorTest(t)
			defer vt.TearDown()

			g := NewWithT(t)
			vt.WriteEmails(t, tc.allowedEmails)
			validator := vt.NewValidator(tc.allowedDomains, nil)
			authorized := validator(tc.email)
			g.Expect(authorized).To(Equal(tc.expectedAuthZ))
		})
	}
}
