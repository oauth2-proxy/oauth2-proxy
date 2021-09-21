package basic

import (
	// We support SHA1 & bcrypt in HTPasswd
	"crypto/sha1" // #nosec G505
	"encoding/base64"
	"encoding/csv"
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
	mutex sync.RWMutex
}

// bcryptPass is used to identify bcrypt passwords in the
// htpasswdMap users.
type bcryptPass string

// sha1Pass os used to identify sha1 passwords in the
// htpasswdMap users.
type sha1Pass string

// NewHTPasswdValidator constructs an httpasswd based validator from the file
// at the path given.
func NewHTPasswdValidator(usersFile string, done <-chan bool, onUpdate func()) (Validator, error) {
	return newHTPasswdMap(usersFile, done, onUpdate), nil
}

func newHTPasswdMap(usersFile string, done <-chan bool, onUpdate func()) *htpasswdMap {
	hm := &htpasswdMap{users: make(map[string]interface{})}
	if usersFile != "" {
		watcher.WatchForUpdates(usersFile, done, func() {
			hm.loadHTPasswdFile(usersFile)
			onUpdate()
		})
		hm.loadHTPasswdFile(usersFile)
	}

	return hm
}

func (hm *htpasswdMap) loadHTPasswdFile(usersFile string) {
	r, err := os.Open(usersFile) // #nosec G304
	if err != nil {
		logger.Fatalf("could not open htpasswd file=%q, %s", usersFile, err)
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
		logger.Errorf("could not read htpasswd file=%q, %s", usersFile, err)
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

	hm.mutex.RLock()
	hm.users = updated
	hm.mutex.RUnlock()
}

// Validate checks a users password against the htpasswd entries
func (hm *htpasswdMap) Validate(user string, password string) bool {
	realPassword, exists := hm.users[user]
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
