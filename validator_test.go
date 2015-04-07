package main

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestValidatorComparisonsAreCaseInsensitive(t *testing.T) {
	auth_email_file, err := ioutil.TempFile("", "test_auth_emails_")
	if err != nil {
		t.Fatal("failed to create temp file: " + err.Error())
	}
	defer os.Remove(auth_email_file.Name())

	auth_email_file.WriteString(
		strings.Join([]string{"Foo.Bar@Example.Com"}, "\n"))
	err = auth_email_file.Close()
	if err != nil {
		t.Fatal("failed to close temp file " + auth_email_file.Name() +
			": " + err.Error())
	}

	domains := []string{"Frobozz.Com"}
	validator := NewValidator(domains, auth_email_file.Name())

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
