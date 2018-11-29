// +build go1.3,!plan9,!solaris

package main

import (
	"io/ioutil"
	"os"
	"testing"
)

func (vt *ValidatorTest) UpdateEmailFile(t *testing.T, emails []string) {
	var err error
	vt.authEmailFile, err = os.OpenFile(
		vt.authEmailFile.Name(), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal("failed to re-open temp file for updates")
	}
	vt.WriteEmails(t, emails)
}

func (vt *ValidatorTest) UpdateEmailFileViaRenameAndReplace(
	t *testing.T, emails []string) {
	origFile := vt.authEmailFile
	var err error
	vt.authEmailFile, err = ioutil.TempFile("", "test_auth_emails_")
	if err != nil {
		t.Fatal("failed to create temp file for rename and replace: " +
			err.Error())
	}
	vt.WriteEmails(t, emails)

	movedName := origFile.Name() + "-moved"
	err = os.Rename(origFile.Name(), movedName)
	err = os.Rename(vt.authEmailFile.Name(), origFile.Name())
	if err != nil {
		t.Fatal("failed to rename and replace temp file: " +
			err.Error())
	}
	vt.authEmailFile = origFile
	os.Remove(movedName)
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

	vt.UpdateEmailFile(t, []string{
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

func TestValidatorOverwriteEmailListViaRenameAndReplace(t *testing.T) {
	vt := NewValidatorTest(t)
	defer vt.TearDown()

	vt.WriteEmails(t, []string{"xyzzy@example.com"})
	domains := []string(nil)
	updated := make(chan bool, 1)
	validator := vt.NewValidator(domains, updated)

	if !validator("xyzzy@example.com") {
		t.Error("email in list should validate")
	}

	vt.UpdateEmailFileViaRenameAndReplace(t, []string{"plugh@example.com"})
	<-updated

	if validator("xyzzy@example.com") {
		t.Error("email removed from list should not validate")
	}
}
