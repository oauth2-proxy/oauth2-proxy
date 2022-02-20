package util

// BoolPtr returns a pointer to a boolean value.
// As long as bool defaults to false when populated from JSON with `omitempty`,
// it is not possible to distinguish `omitempty`-default from intentional false.
// Boolean pointers default to nil when `omitempty`, allowing to distinguish
// default from false.
func BoolPtr(b bool) *bool {
	return &b
}
