package main

import (
	"strings"
)

// StringArray is a type alias for a slice of strings
type StringArray []string

// Get returns the slice of strings
func (a *StringArray) Get() interface{} {
	return []string(*a)
}

// Set appends a string to the StringArray
func (a *StringArray) Set(s string) error {
	*a = append(*a, s)
	return nil
}

// String joins elements of the StringArray into a single comma separated string
func (a *StringArray) String() string {
	return strings.Join(*a, ",")
}
