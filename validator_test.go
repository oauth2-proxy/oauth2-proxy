package main

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
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

func TestValidatorEmpty(t *testing.T) {
	vt := NewValidatorTest(t)
	defer vt.TearDown()

	vt.WriteEmails(t, []string(nil))
	domains := []string(nil)
	validator := vt.NewValidator(domains, nil)

	if validator("foo.bar@example.com") {
		t.Error("nothing should validate when the email and " +
			"domain lists are empty")
	}
}

func TestValidatorSingleEmail(t *testing.T) {
	vt := NewValidatorTest(t)
	defer vt.TearDown()

	vt.WriteEmails(t, []string{"foo.bar@example.com"})
	domains := []string(nil)
	validator := vt.NewValidator(domains, nil)

	if !validator("foo.bar@example.com") {
		t.Error("email should validate")
	}
	if validator("baz.quux@example.com") {
		t.Error("email from same domain but not in list " +
			"should not validate when domain list is empty")
	}
}

func TestValidatorSingleDomain(t *testing.T) {
	vt := NewValidatorTest(t)
	defer vt.TearDown()

	vt.WriteEmails(t, []string(nil))
	domains := []string{"example.com"}
	validator := vt.NewValidator(domains, nil)

	if !validator("foo.bar@example.com") {
		t.Error("email should validate")
	}
	if !validator("baz.quux@example.com") {
		t.Error("email from same domain should validate")
	}
}

func TestValidatorMultipleEmailsMultipleDomains(t *testing.T) {
	vt := NewValidatorTest(t)
	defer vt.TearDown()

	vt.WriteEmails(t, []string{
		"xyzzy@example.com",
		"plugh@example.com",
	})
	domains := []string{"example0.com", "example1.com"}
	validator := vt.NewValidator(domains, nil)

	if !validator("foo.bar@example0.com") {
		t.Error("email from first domain should validate")
	}
	if !validator("baz.quux@example1.com") {
		t.Error("email from second domain should validate")
	}
	if !validator("xyzzy@example.com") {
		t.Error("first email in list should validate")
	}
	if !validator("plugh@example.com") {
		t.Error("second email in list should validate")
	}
	if validator("xyzzy.plugh@example.com") {
		t.Error("email not in list that matches no domains " +
			"should not validate")
	}
}

func TestValidatorComparisonsAreCaseInsensitive(t *testing.T) {
	vt := NewValidatorTest(t)
	defer vt.TearDown()

	vt.WriteEmails(t, []string{"Foo.Bar@Example.Com"})
	domains := []string{"Frobozz.Com"}
	validator := vt.NewValidator(domains, nil)

	if !validator("foo.bar@example.com") {
		t.Error("loaded email addresses are not lower-cased")
	}
	if !validator("Foo.Bar@Example.Com") {
		t.Error("validated email addresses are not lower-cased")
	}
	if !validator("foo.bar@frobozz.com") {
		t.Error("loaded domains are not lower-cased")
	}
	if !validator("foo.bar@Frobozz.Com") {
		t.Error("validated domains are not lower-cased")
	}
}

func TestValidatorIgnoreSpacesInAuthEmails(t *testing.T) {
	vt := NewValidatorTest(t)
	defer vt.TearDown()

	vt.WriteEmails(t, []string{"   foo.bar@example.com   "})
	domains := []string(nil)
	validator := vt.NewValidator(domains, nil)

	if !validator("foo.bar@example.com") {
		t.Error("email should validate")
	}
}

func TestValidatorOverwriteEmailListDirectly(t *testing.T) {
	vt := NewValidatorTest(t)
	defer vt.TearDown()

	vt.WriteEmails(t, []string{
		"xyzzy@example.com",
		"plugh@example.com",
	})
	domains := []string(nil)
	updated := make(chan bool)
	validator := vt.NewValidator(domains, updated)

	if !validator("xyzzy@example.com") {
		t.Error("first email in list should validate")
	}
	if !validator("plugh@example.com") {
		t.Error("second email in list should validate")
	}
	if validator("xyzzy.plugh@example.com") {
		t.Error("email not in list that matches no domains " +
			"should not validate")
	}

	vt.WriteEmails(t, []string{
		"xyzzy.plugh@example.com",
		"plugh@example.com",
	})
	<-updated

	if validator("xyzzy@example.com") {
		t.Error("email removed from list should not validate")
	}
	if !validator("plugh@example.com") {
		t.Error("email retained in list should validate")
	}
	if !validator("xyzzy.plugh@example.com") {
		t.Error("email added to list should validate")
	}
}
