package ptr

func Bool(v bool) *bool       { return &v }
func String(v string) *string { return &v }
func Int(v int) *int          { return &v }

// Ptr generically returns a pointer to the given value.
func Ptr[T any](v T) *T {
	return &v
}

// Deref returns the value of the pointer or def(ault) if nil.
func Deref[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}
