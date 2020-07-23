package validation

func prefixValues(prefix string, values ...string) []string {
	msgs := make([]string, len(values))
	for i, value := range values {
		msgs[i] = prefix + value
	}
	return msgs
}
