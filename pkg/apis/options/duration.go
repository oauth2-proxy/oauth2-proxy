package options

import (
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"
)

// Duration is an alias for time.Duration so that we can ensure the marshalling
// and unmarshalling of string durations is done as users expect.
// Intentional blank line below to keep this first part of the comment out of
// any generated references.

// Duration is as string representation of a period of time.
// A duration string is a is a possibly signed sequence of decimal numbers,
// each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".

// Conversion from string or floating point to golang duration type
// This way floating points will be converted to seconds and strings
// of type 3s or 5m will be parsed with time.ParseDuration
func toDurationHookFunc() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if t != reflect.TypeOf(time.Duration(0)) {
			return data, nil
		}

		switch f.Kind() {
		case reflect.String:
			return time.ParseDuration(data.(string))
		case reflect.Float64:
			return time.Duration(data.(float64) * float64(time.Second)), nil
		case reflect.Int64:
			return time.Duration(data.(int64)), nil
		default:
			return data, nil
		}
	}
}
