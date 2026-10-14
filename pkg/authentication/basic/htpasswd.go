package basic

import (
	// We support SHA1 & bcrypt in HTPasswd
	"crypto/sha1" // #nosec G505
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"os"
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

	if err := h.loadHTPasswdFile(path); err != nil {
		return nil, fmt.Errorf("could not load htpasswd file: %v", err)
	}

	if err := watcher.WatchFileForUpdates(path, nil, func() {
		err := h.loadHTPasswdFile(path)
		if err != nil {
			logger.Errorf("%v: no changes were made to the current htpasswd map", err)
		}
	}); err != nil {
		return nil, fmt.Errorf("could not watch htpasswd file: %v", err)
	}

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
		return fmt.Errorf("could not read htpasswd file: %v", err)
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

// createHtpasswdMap constructs an htpasswdMap from the given records
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
			invalidEntries = passShaOrBcrypt(h, user, realPassword)
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
		return nil, fmt.Errorf("could not construct htpasswdMap: htpasswd file doesn't contain a single valid user entry")
	}

	return h, nil
}

// passShaOrBcrypt checks if a htpasswd entry is valid and the password is encrypted with SHA or bcrypt.
// Valid user entries are saved in the htpasswdMap, invalid records are reurned.
func passShaOrBcrypt(h *htpasswdMap, user, password string) (invalidEntries []string) {
	passLen := len(password)
	switch {
	case passLen > 6 && password[:5] == "{SHA}":
		h.users[user] = sha1Pass(password[5:])
	case passLen > 5 &&
		(password[:4] == "$2b$" ||
			password[:4] == "$2y$" ||
			password[:4] == "$2x$" ||
			password[:4] == "$2a$"):
		h.users[user] = bcryptPass(password)
	default:
		invalidEntries = append(invalidEntries, user)
	}

	return invalidEntries
}

// GetUsers return a "thread safe" copy of the internal user list
func (h *htpasswdMap) GetUsers() map[string]interface{} {
	newUserList := make(map[string]interface{})
	h.rwm.Lock()
	for key, value := range h.users {
		newUserList[key] = value
	}
	h.rwm.Unlock()
	return newUserList
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
