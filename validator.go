package main

import (
	"crypto"
	"encoding/csv"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/jmespath/go-jmespath"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

// UserMap holds information from the authenticated emails file
type UserMap struct {
	usersFile string
	m         unsafe.Pointer
}

// NewUserMap parses the authenticated emails file into a new UserMap
func NewUserMap(usersFile string, done <-chan bool, onUpdate func()) *UserMap {
	um := &UserMap{usersFile: usersFile}
	m := make(map[string]bool)
	atomic.StorePointer(&um.m, unsafe.Pointer(&m))
	if usersFile != "" {
		logger.Printf("using authenticated emails file %s", usersFile)
		WatchForUpdates(usersFile, done, func() {
			um.LoadAuthenticatedEmailsFile()
			onUpdate()
		})
		um.LoadAuthenticatedEmailsFile()
	}
	return um
}

// IsValid checks if an email is allowed
func (um *UserMap) IsValid(email string) (result bool) {
	m := *(*map[string]bool)(atomic.LoadPointer(&um.m))
	_, result = m[email]
	return
}

// LoadAuthenticatedEmailsFile loads the authenticated emails file from disk
// and parses the contents as CSV
func (um *UserMap) LoadAuthenticatedEmailsFile() {
	r, err := os.Open(um.usersFile)
	if err != nil {
		logger.Fatalf("failed opening authenticated-emails-file=%q, %s", um.usersFile, err)
	}
	defer r.Close()
	csvReader := csv.NewReader(r)
	csvReader.Comma = ','
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true
	records, err := csvReader.ReadAll()
	if err != nil {
		logger.Printf("error reading authenticated-emails-file=%q, %s", um.usersFile, err)
		return
	}
	updated := make(map[string]bool)
	for _, r := range records {
		address := strings.ToLower(strings.TrimSpace(r[0]))
		updated[address] = true
	}
	atomic.StorePointer(&um.m, unsafe.Pointer(&updated))
}

func newValidatorImpl(domains []string, usersFile string,
	done <-chan bool, onUpdate func()) func(string) bool {
	validUsers := NewUserMap(usersFile, done, onUpdate)

	var allowAll bool
	for i, domain := range domains {
		if domain == "*" {
			allowAll = true
			continue
		}
		domains[i] = fmt.Sprintf("@%s", strings.ToLower(domain))
	}

	validator := func(email string) (valid bool) {
		if email == "" {
			return
		}
		email = strings.ToLower(email)
		for _, domain := range domains {
			valid = valid || strings.HasSuffix(email, domain)
		}
		if !valid {
			valid = validUsers.IsValid(email)
		}
		if allowAll {
			valid = true
		}
		return valid
	}
	return validator
}

// NewValidator constructs a function to validate email addresses
func NewValidator(domains []string, usersFile string) func(string) bool {
	return newValidatorImpl(domains, usersFile, nil, func() {})
}

// JMESValidator contains a set of compiled <https://jmespath.org> expressions
// that can be used validate a deserialized json value (such as an OAuth claims
// object) using the MatchesAny() function.
type JMESValidator struct {
	rules         []string
	compiledRules []*jmespath.JMESPath
	rulesHash     []byte
}

// IsEmpty will return true if no valid rules have been added.
func (v *JMESValidator) IsEmpty() bool {
	return len(v.rules) == 0
}

// truthy() is anything that's not "falsy", or in this case "nothing-y" is probably
// more accurate. False values are: [], {}, "", `false`, and `nil`. Notably, any
// numeric value is true (including 0).
//   https://jmespath.org/specification.html#or-expressions
func truthy(result interface{}) bool {

	switch v := result.(type) {
	case bool:
		return v
	case []interface{}:
		return len(v) > 0
	case map[string]interface{}:
		return len(v) > 0
	case string:
		return len(v) > 0
	case nil:
		return false
	}

	// go-jmespath does extra validation as well, we should keep parity
	rv := reflect.ValueOf(result)
	switch rv.Kind() {
	case reflect.Struct:
		// Structs are not the same as an empty map (i.e. they are "something"
		// even if all 0's of something), thus true here.
		return true
	case reflect.Slice, reflect.Map:
		return rv.Len() > 0
	case reflect.Ptr:
		if rv.IsNil() {
			return false
		}
		// If a pointer, check the pointed at value.
		elem := rv.Elem()
		return truthy(elem.Interface())
	}

	return true
}

// AddRule will attempt to compile the given JMESpath expression and append it
// to the list of rules to check if it is valid. If the expression is empty
// or the first non-whitespace character starts with a "#", it is ignored and
// treated as a comment.
// Returns true if a rule was successfully added to the validator. If there
// was an error with the expression, an error will be returned.
func (v *JMESValidator) AddRule(jmespathExpr string) (bool, error) {

	// TODO: Check for duplicate rules and warn?

	rule := strings.TrimSpace(jmespathExpr)
	if rule == "" || strings.HasPrefix(rule, "#") {
		// Not an error, but nothing as added either (empty or commented rule)
		return false, nil
	}

	var compiled *jmespath.JMESPath
	var err error

	if compiled, err = jmespath.Compile(rule); err != nil {
		return false, fmt.Errorf("invalid jmespath expression (%q): %v", rule, err)
	}

	// Invalidate the hash if it had been requested yet
	v.rulesHash = nil
	v.rules = append(v.rules, rule)
	v.compiledRules = append(v.compiledRules, compiled)

	return true, nil
}

// Rules will return the current set of valid registered rules (in source form).
// Edits to these rules do not affect the internal validation as they have already
// been pre-compiled by the time they are added to this list.
func (v *JMESValidator) Rules() []string {
	return v.rules
}

// RulesHash returns a deterministic hashed value of the input rules that have been
// registered in this validator. It's meant to serve as a quick way to know if the
// set of rules has changed over time.
func (v *JMESValidator) RulesHash() []byte {

	if v.rulesHash != nil {
		return v.rulesHash
	}

	if len(v.rules) == 0 {
		return nil
	}

	// Create a hash of our rules (in source form) so that we can know
	// if they have changed since they were last run against something
	h := crypto.SHA256.New()
	for _, rule := range v.rules {
		h.Write([]byte(rule))
	}

	v.rulesHash = h.Sum(nil)

	return v.rulesHash
}

// MatchesAny will scan the list of compiled rules, in order, and return true
// on the first match. If the provided data parameter is nil, or no rules
// match, return false. Note: an empty set of rules does NOT return true,
// since at least one rule must match. If a match is found, returns true as
// well as the index of the rule that was successfully matched.
func (v *JMESValidator) MatchesAny(data map[string]interface{}) (bool, int) {

	if data == nil {
		return false, -1
	}

	for idx, rule := range v.compiledRules {
		if result, err := rule.Search(data); err == nil {
			if truthy(result) {
				return true, idx
			}
		}
	}

	return false, -1
}
