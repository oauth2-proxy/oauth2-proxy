package basic

import (
	// We support SHA1 & bcrypt in HTPasswd
	"crypto/sha1" // #nosec G505
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"golang.org/x/crypto/bcrypt"
)

// htpasswdMap represents the structure of an htpasswd file.
// Passwords must be generated with -B for bcrypt or -s for SHA1.
type htpasswdMap struct {
	users map[string]interface{}
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
	// We allow HTPasswd location via config options
	r, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("could not open htpasswd file: %v", err)
	}
	defer func(c io.Closer) {
		cerr := c.Close()
		if cerr != nil {
			logger.Fatalf("error closing the htpasswd file: %v", cerr)
		}
	}(r)
	return newHtpasswd(r)
}

// newHtpasswd consctructs an htpasswd from an io.Reader (an opened file).
func newHtpasswd(file io.Reader) (*htpasswdMap, error) {
	csvReader := csv.NewReader(file)
	csvReader.Comma = ':'
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true

	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("could not read htpasswd file: %v", err)
	}

	return createHtpasswdMap(records)
}

// createHtasswdMap constructs an htpasswdMap from the given records
func createHtpasswdMap(records [][]string) (*htpasswdMap, error) {
	h := &htpasswdMap{users: make(map[string]interface{})}
	for _, record := range records {
		user, realPassword := record[0], record[1]
		shaPrefix := realPassword[:5]
		if shaPrefix == "{SHA}" {
			h.users[user] = sha1Pass(realPassword[5:])
			continue
		}

		bcryptPrefix := realPassword[:4]
		if bcryptPrefix == "$2a$" || bcryptPrefix == "$2b$" || bcryptPrefix == "$2x$" || bcryptPrefix == "$2y$" {
			h.users[user] = bcryptPass(realPassword)
			continue
		}

		// Password is neither sha1 or bcrypt
		// TODO(JoelSpeed): In the next breaking release, make this return an error.
		logger.Errorf("Invalid htpasswd entry for %s. Must be a SHA or bcrypt entry.", user)
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
