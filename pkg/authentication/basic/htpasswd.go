package basic

import (
	// We support SHA1 & bcrypt in HTPasswd
	"crypto/sha1" // #nosec G505
	"encoding/base64"
	"encoding/csv"
	"io"
	"os"
	"sync/atomic"
	"unsafe"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/watcher"
	"golang.org/x/crypto/bcrypt"
)

// HtpasswdMap represents the structure of an htpasswd file.
// Passwords must be generated with -B for bcrypt or -s for SHA1.
type HtpasswdMap struct {
	usersFile string
	m         unsafe.Pointer
}

// bcryptPass is used to identify bcrypt passwords in the
// htpasswdMap users.
type bcryptPass string

// sha1Pass os used to identify sha1 passwords in the
// htpasswdMap users.
type sha1Pass string

// NewHTPasswdValidator constructs an httpasswd based validator from the file
// at the path given.
func NewHTPasswdValidator(path string) func(string, string) bool {
	return newHTPasswdValidatorImpl(path, nil, func() {})
}

func newHTPasswdValidatorImpl(path string,
	done <-chan bool, onUpdate func()) func(string, string) bool {

	// get users
	validUsers := NewHTPasswdMap(path, done, onUpdate)

	validator := func(user string, password string) (valid bool) {
		if user == "" || password == "" {
			return
		}

		return validUsers.IsValid(user, password)
	}
	return validator
}

func NewHTPasswdMap(usersFile string, done <-chan bool, onUpdate func()) *HtpasswdMap {
	um := &HtpasswdMap{usersFile: usersFile}
	m := make(map[string]interface{})
	atomic.StorePointer(&um.m, unsafe.Pointer(&m)) // #nosec G103
	if usersFile != "" {
		logger.Printf("using htpasswd file %s", usersFile)
		watcher.WatchForUpdates(usersFile, done, func() {
			um.LoadHTPasswdFile()
			onUpdate()
		})
		um.LoadHTPasswdFile()
	}
	return um
}

func (um *HtpasswdMap) LoadHTPasswdFile() {
	r, err := os.Open(um.usersFile) // #nosec G304
	if err != nil {
		logger.Fatalf("fcould not open htpasswd file=%q, %s", um.usersFile, err)
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
		logger.Errorf("could not read htpasswd file=%q, %s", um.usersFile, err)
		return
	}

	updated := make(map[string]interface{})
	for _, record := range records {
		user, realPassword := record[0], record[1]
		shaPrefix := realPassword[:5]
		if shaPrefix == "{SHA}" {
			updated[user] = sha1Pass(realPassword[5:])
			continue
		}

		bcryptPrefix := realPassword[:4]
		if bcryptPrefix == "$2a$" || bcryptPrefix == "$2b$" || bcryptPrefix == "$2x$" || bcryptPrefix == "$2y$" {
			updated[user] = bcryptPass(realPassword)
			continue
		}

		// Password is neither sha1 or bcrypt
		// TODO(JoelSpeed): In the next breaking release, make this return an error.
		logger.Errorf("Invalid htpasswd entry for %s. Must be a SHA or bcrypt entry.", user)
	}
	atomic.StorePointer(&um.m, unsafe.Pointer(&updated)) // #nosec G103
}

// Validate checks a users password against the htpasswd entries
func (um *HtpasswdMap) IsValid(user string, password string) bool {
	m := *(*map[string]interface{})(atomic.LoadPointer(&um.m))

	realPassword, exists := m[user]
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
