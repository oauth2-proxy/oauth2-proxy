package claims

import (
	"fmt"
	"log"
	"math"
	"net/http"
	"reflect"
	"time"
)

func EncodeHeaders(h http.Header, claims map[string]interface{}) {
	reflectValue(h, reflect.ValueOf(claims))
}

// valueString returns the string representation of a value.
func valueString(v reflect.Value) string {
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}

	if v.Kind() == reflect.Bool {
		if v.Bool() {
			return "1"
		}
		return "0"
	}

	if v.Type() == reflect.TypeOf(time.Time{}) {
		t := v.Interface().(time.Time)
		return t.Format(http.TimeFormat)
	}

	return fmt.Sprint(v.Interface())
}

func reflectValue(header http.Header, val reflect.Value) error {
	var embedded []reflect.Value

	iter := val.MapRange()
	for iter.Next() {
		name := iter.Key().String()
		sv := iter.Value()

		switch t := sv.Interface().(type) {
		case int:
			//log.Printf("%s => %s", name, string(t))
			header.Add(name, string(t))
			continue
		case float64:
			if name == "exp" || name == "nbf" || name == "iat" {
				// well-known time entries
				sec, dec := math.Modf(t)
				vv := time.Unix(int64(sec), int64(dec*1e9))
				header.Add(name, vv.Format(http.TimeFormat))
			} else {
				header.Add(name, fmt.Sprintf("%f", t))
			}
			continue
		case string:
			//log.Printf("%s => %v", name, t)
			header.Add(name, t)
			continue
		case bool:
			//log.Printf("%s => %v", name, t)
			if t {
				header.Add(name, "true")
			} else {
				header.Add(name, "false")
			}
			continue
		case []interface{}: // array
			for _, item := range t {
				vv := valueString(reflect.ValueOf(item))
				//log.Printf("%s[%d] ==> %s", name, i, vv)
				header.Add(name, vv)
			}
			continue
		case map[string]interface{}: // map
			//log.Printf("%s => %v", name, t)
			for key, item := range t {
				vv := valueString(reflect.ValueOf(item))
				//log.Printf("%s[%s] ==> %s", name, key, vv)
				header.Add(fmt.Sprintf("%s_%s", name, key), vv)
			}
			continue
		default:
			log.Printf("%s unknown cast => %v", name, t)
			continue
		}
	}

	for _, f := range embedded {
		if err := reflectValue(header, f); err != nil {
			return err
		}
	}

	return nil
}
