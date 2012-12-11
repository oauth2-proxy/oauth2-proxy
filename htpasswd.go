package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"log"
	"os"
)

// lookup passwords in a htpasswd file
// The entries must have been created with -s for SHA encryption

type HtpasswdFile struct {
	Users map[string]string
}

func NewHtpasswdFile(path string) *HtpasswdFile {
	log.Printf("using htpasswd file %s", path)
	r, err := os.Open(path)
	if err != nil {
		log.Fatalf("failed opening %v, %s", path, err.Error())
	}
	csv_reader := csv.NewReader(r)
	csv_reader.Comma = ':'
	csv_reader.Comment = '#'
	csv_reader.TrimLeadingSpace = true

	records, err := csv_reader.ReadAll()
	if err != nil {
		log.Fatalf("Failed reading file %s", err.Error())
	}
	h := &HtpasswdFile{Users: make(map[string]string)}
	for _, record := range records {
		h.Users[record[0]] = record[1]
	}
	return h
}

func (h *HtpasswdFile) Validate(user string, password string) bool {
	realPassword, exists := h.Users[user]
	if !exists {
		return false
	}
	if realPassword[:5] == "{SHA}" {
		d := sha1.New()
		d.Write([]byte(password))
		if realPassword[5:] == base64.StdEncoding.EncodeToString(d.Sum(nil)) {
			return true
		}
	} else {
		log.Printf("Invalid htpasswd entry for %s. Must be a SHA entry.", user)
	}
	return false
}
