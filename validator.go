package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"
)

func NewValidator(domain string, usersFile string) func(string) bool {

	validUsers := make(map[string]bool)
	emailSuffix := ""
	if domain != "" {
		emailSuffix = fmt.Sprintf("@%s", domain)
	}

	if usersFile != "" {
		r, err := os.Open(usersFile)
		if err != nil {
			log.Fatalf("failed opening -authenticated-emails-file=%v, %s", usersFile, err.Error())
		}
		csv_reader := csv.NewReader(r)
		csv_reader.Comma = ','
		csv_reader.Comment = '#'
		csv_reader.TrimLeadingSpace = true
		records, err := csv_reader.ReadAll()
		for _, r := range records {
			validUsers[r[0]] = true
		}
	}

	validator := func(email string) bool {
		var valid bool
		if emailSuffix != "" {
			valid = strings.HasSuffix(email, emailSuffix)
		}
		if !valid {
			_, valid = validUsers[email]
		}
		log.Printf("validating: is %s valid? %v", email, valid)
		return valid
	}
	return validator
}
