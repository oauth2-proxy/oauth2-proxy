package validation

func prefixValues(prefix string, values ...string) []string {
	msgs := []string{}
	for _, value := range values {
		if value != "" {
			msgs = append(msgs, prefix+value)
		}
	}
	return msgs
}
