package basic

// Validator is a minimal interface for something that can validate a
// username and password combination.
type Validator interface {
	Validate(user, password string) bool
}
