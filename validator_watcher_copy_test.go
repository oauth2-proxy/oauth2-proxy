// +build go1.3,!plan9,!solaris,!windows

// Turns out you can't copy over an existing file on Windows.

package main

import (
	"io/ioutil"
	"os"
	"testing"
)

func (vt *ValidatorTest) UpdateEmailFileViaCopyingOver(
	t *testing.T, emails []string) {
	orig_file := vt.auth_email_file
	var err error
	vt.auth_email_file, err = ioutil.TempFile("", "test_auth_emails_")
	if err != nil {
		t.Fatal("failed to create temp file for copy: " + err.Error())
	}
	vt.WriteEmails(t, emails)
	err = os.Rename(vt.auth_email_file.Name(), orig_file.Name())
	if err != nil {
		t.Fatal("failed to copy over temp file: " + err.Error())
	}
	vt.auth_email_file = orig_file
}

func TestValidatorOverwriteEmailListViaCopyingOver(t *testing.T) {
	vt := NewValidatorTest(t)
	defer vt.TearDown()

	vt.WriteEmails(t, []string{"xyzzy@example.com"})
	domains := []string(nil)
	updated := make(chan bool)
	validator := vt.NewValidator(domains, updated)

	if !validator("xyzzy@example.com") {
		t.Error("email in list should validate")
	}

	vt.UpdateEmailFileViaCopyingOver(t, []string{"plugh@example.com"})
	<-updated

	if validator("xyzzy@example.com") {
		t.Error("email removed from list should not validate")
	}
}
