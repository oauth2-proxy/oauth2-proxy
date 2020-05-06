package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadTemplates(t *testing.T) {
	dir, err := ioutil.TempDir("", "templatetest")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	templateHTML := `{{.TestString}} {{.TestString | ToLower}} {{.TestString | ToUpper}}`
	signInFile := filepath.Join(dir, "sign_in.html")
	if err := ioutil.WriteFile(signInFile, []byte(templateHTML), 0666); err != nil {
		log.Fatal(err)
	}
	errorFile := filepath.Join(dir, "error.html")
	if err := ioutil.WriteFile(errorFile, []byte(templateHTML), 0666); err != nil {
		log.Fatal(err)
	}
	templates := loadTemplates(dir)
	assert.NotEqual(t, templates, nil)

	data := struct {
		TestString string
	}{
		TestString: "Testing",
	}

	var sitpl bytes.Buffer
	templates.ExecuteTemplate(&sitpl, "sign_in.html", data)
	assert.Equal(t, "Testing testing TESTING", sitpl.String())

	var errtpl bytes.Buffer
	templates.ExecuteTemplate(&errtpl, "error.html", data)
	assert.Equal(t, "Testing testing TESTING", errtpl.String())
}

func TestTemplatesCompile(t *testing.T) {
	templates := getTemplates()
	assert.NotEqual(t, templates, nil)
}
