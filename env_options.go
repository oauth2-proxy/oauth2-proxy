package main

import (
	"os"
	"reflect"
	"strings"
)

// EnvOptions holds program options loaded from the process environment
type EnvOptions map[string]interface{}

// LoadEnvForStruct loads environment variables for each field in an options
// struct passed into it.
//
// Fields in the options struct must have an `env` and `cfg` tag to be read
// from the environment
func (cfg EnvOptions) LoadEnvForStruct(options interface{}) {
	val := reflect.ValueOf(options)
	var typ reflect.Type
	if val.Kind() == reflect.Ptr {
		typ = val.Elem().Type()
	} else {
		typ = val.Type()
	}

	for i := 0; i < typ.NumField(); i++ {
		// pull out the struct tags:
		//    flag - the name of the command line flag
		//    deprecated - (optional) the name of the deprecated command line flag
		//    cfg - (optional, defaults to underscored flag) the name of the config file option
		field := typ.Field(i)
		fieldV := reflect.Indirect(val).Field(i)

		if field.Type.Kind() == reflect.Struct && field.Anonymous {
			cfg.LoadEnvForStruct(fieldV.Interface())
			continue
		}

		flagName := field.Tag.Get("flag")
		envName := field.Tag.Get("env")
		cfgName := field.Tag.Get("cfg")
		if cfgName == "" && flagName != "" {
			cfgName = strings.ReplaceAll(flagName, "-", "_")
		}
		if envName == "" || cfgName == "" {
			// resolvable fields must have the `env` and `cfg` struct tag
			continue
		}
		v := os.Getenv(envName)
		if v != "" {
			cfg[cfgName] = v
		}
	}
}
