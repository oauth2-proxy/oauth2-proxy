package main

import (
	"crypto"
	"encoding/csv"
	"fmt"
	"math"
	"os"
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

type JMESValidator struct {
	rules         []string
	compiledRules []*jmespath.JMESPath
	rulesHash     []byte
}

func (v *JMESValidator) IsEmpty() bool {
	return len(v.rules) == 0
}

// truthy() is anything that's not "falsy" (i.e. false, 0, 0.0, "", nil, and NaN)
// Since this is JSON-centric (intended for checking claims) it follows the rules here:
//  https://developer.mozilla.org/en-US/docs/Glossary/Truthy
func truthy(result interface{}) bool {
	switch v := result.(type) {
	case int:
		return v != 0
	case uint:
		return v != 0
	case int32:
		return v != 0
	case uint32:
		return v != 0
	case int64:
		return v != 0
	case uint64:
		return v != 0
	case string:
		return v != ""
	case float32:
		return !math.IsNaN(float64(v)) && v != 0.0
	case float64:
		return !math.IsNaN(v) && v != 0.0
	case bool:
		return v
	}
	// Notably, [] and {} are truthy. Only nil is falsy.
	return result != nil
}

func (v *JMESValidator) AddRule(jmespathExpr string) (bool, error) {

	// TODO: Check for duplicate rules?

	rule := strings.TrimSpace(jmespathExpr)
	if rule != "" && !strings.HasPrefix(rule, "#") {
		var compiled *jmespath.JMESPath
		var err error

		if compiled, err = jmespath.Compile(rule); err != nil {
			return false, fmt.Errorf("invalid claim assertion (%q): %v", rule, err)
		}

		// Invalidate the hash if it had been requested yet
		v.rulesHash = nil
		v.rules = append(v.rules, rule)
		v.compiledRules = append(v.compiledRules, compiled)

		return true, nil
	}

	// Not an error, but nothing as added either (empty or commented rule)
	return false, nil
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

	if v.rulesHash == nil && len(v.rules) > 0 {

		// Create a hash of our rules (in source form) so that we can know
		// if they have changed since they were last run against something
		h := crypto.SHA256.New()
		for _, rule := range v.rules {
			h.Write([]byte(rule))
		}

		v.rulesHash = h.Sum(nil)
	}

	return v.rulesHash
}

// MatchesAny will scan the list of compiled rules, in order, and return true
// on the first match. If the provided data parameter is nil, or no rules
// match, return false. Note: an empty set of rules does NOT return true,
// since at least one rule must match. If a match is found, returns true as
// well as the index of the rule that was successfully matched.
func (v *JMESValidator) MatchesAny(data map[string]interface{}) (bool, int) {

	// if s, err := json.MarshalIndent(data, "", "  "); err == nil {
	// 	logger.Printf("CLAIMS: %s", string(s))
	// }

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
