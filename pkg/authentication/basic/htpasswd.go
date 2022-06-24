package basic

import (
	// We support SHA1 & bcrypt in HTPasswd
	"crypto/sha1" // #nosec G505
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/watcher"
	"golang.org/x/crypto/bcrypt"
)

// htpasswdMap represents the structure of an htpasswd file.
// Passwords must be generated with -B for bcrypt or -s for SHA1.
type htpasswdMap struct {
	users map[string]interface{}
	rwm   sync.RWMutex
}

// bcryptPass is used to identify bcrypt passwords in the
// htpasswdMap users.
type bcryptPass string

// sha1Pass os used to identify sha1 passwords in the
// htpasswdMap users.
type sha1Pass string

// NewHTPasswdValidator constructs an httpasswd based validator from the file
// at the path given.
func NewHTPasswdValidator(path string) (Validator, error) {
	h := &htpasswdMap{users: make(map[string]interface{})}

	err := h.loadHTPasswdFile(path)
	if err != nil {
		return nil, err
	}

	watcher.WatchFileForUpdates(path, nil, func() {
		err := h.loadHTPasswdFile(path)
		if err != nil {
			logger.Error(err)
		}
	})

	return h, nil
}

// loadHTPasswdFile loads htpasswd entries from an io.Reader (an opened file) into a htpasswdMap.
func (h *htpasswdMap) loadHTPasswdFile(filename string) error {
	// We allow HTPasswd location via config options
	r, err := os.Open(filename) // #nosec G304
	if err != nil {
		return fmt.Errorf("could not open htpasswd file: %v", err)
	}
	defer func(c io.Closer) {
		cerr := c.Close()
		if cerr != nil {
			logger.Fatalf("error closing the htpasswd file: %v", cerr)
		}
	}(r)

	csvReader := csv.NewReader(r)
	csvReader.Comma = ':'
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true

	records, err := csvReader.ReadAll()
	if err != nil {
		logger.Fatalf("could not read htpasswd file: %v", err)
	}

	updated, err := createHtpasswdMap(records)
	if err != nil {
		return fmt.Errorf("htpasswd entries error: %v", err)
	}

	h.rwm.Lock()
	h.users = updated.users
	h.rwm.Unlock()

	return nil
}

// createHtasswdMap constructs an htpasswdMap from the given records
func createHtpasswdMap(records [][]string) (*htpasswdMap, error) {
	h := &htpasswdMap{users: make(map[string]interface{})}
	var invalidRecords, invalidEntries []string
	for _, record := range records {
		// If a record is invalid or malformed don't panic with index out of range,
		// return a formatted error.
		lr := len(record)
		switch {
		case lr == 2:
			user, realPassword := record[0], record[1]
			if strings.HasPrefix(realPassword, "{SHA}") {
				h.users[user] = sha1Pass(realPassword[5:])
			} else if strings.HasPrefix(realPassword, "$2b$") ||
				strings.HasPrefix(realPassword, "$2y$") ||
				strings.HasPrefix(realPassword, "$2x$") ||
				strings.HasPrefix(realPassword, "$2a$") {
				h.users[user] = bcryptPass(realPassword)
			} else {
				invalidEntries = append(invalidEntries, user)
			}
		case lr == 1, lr > 2:
			invalidRecords = append(invalidRecords, record[0])
		}
	}

	if len(invalidRecords) > 0 {
		return h, fmt.Errorf("invalid htpasswd record(s) %+q", invalidRecords)
	}

	if len(invalidEntries) > 0 {
		return h, fmt.Errorf("'%+q' user(s) could not be added: invalid password, must be a SHA or bcrypt entry", invalidEntries)
	}

	if len(h.users) == 0 {
		logger.Fatal("could not construct htpasswdMap: htpasswd file doesn't contain a single valid user entry")
	}

	return h, nil
}

// Validate checks a users password against the htpasswd entries
func (h *htpasswdMap) Validate(user string, password string) bool {
	realPassword, exists := h.users[user]
	if !exists {
		return false
	}

	switch rp := realPassword.(type) {
	case sha1Pass:
		// We support SHA1 HTPasswd entries
		d := sha1.New() // #nosec G401
		_, err := d.Write([]byte(password))
		if err != nil {
			return false
		}
		return string(rp) == base64.StdEncoding.EncodeToString(d.Sum(nil))
	case bcryptPass:
		return bcrypt.CompareHashAndPassword([]byte(rp), []byte(password)) == nil
	default:
		return false
	}
}
