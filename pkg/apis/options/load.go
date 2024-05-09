package options

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/a8m/envsubst"
	"github.com/ghodss/yaml"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Load reads in the config file at the path given, then merges in environment
// variables (prefixed with `OAUTH2_PROXY`) and finally merges in flags from the flagSet.
// If a config value is unset and the flag has a non-zero value default, this default will be used.
// Eg. A field defined:
//
//	FooBar `cfg:"foo_bar" flag:"foo-bar"`
//
// Can be set in the config file as `foo_bar="baz"`, in the environment as `OAUTH2_PROXY_FOO_BAR=baz`,
// or via the command line flag `--foo-bar=baz`.
func Load(configFileName string, flagSet *pflag.FlagSet, into interface{}) error {
	v := viper.New()
	v.SetConfigFile(configFileName)
	v.SetConfigType("toml") // Config is in toml format
	v.SetEnvPrefix("OAUTH2_PROXY")
	v.AutomaticEnv()
	v.SetTypeByDefaultValue(true)

	if configFileName != "" {
		err := v.ReadInConfig()
		if err != nil {
			return fmt.Errorf("unable to load config file: %w", err)
		}
	}

	err := registerFlags(v, "", flagSet, into)
	if err != nil {
		// This should only happen if there is a programming error
		return fmt.Errorf("unable to register flags: %w", err)
	}

	// UnmarshalExact will return an error if the config includes options that are
	// not mapped to fields of the into struct
	err = v.UnmarshalExact(into, decodeFromCfgTag)
	if err != nil {
		return fmt.Errorf("error unmarshalling config: %w", err)
	}

	return nil
}

// LoadYAML will load a YAML based configuration file into the options interface provided.
func LoadYAML(configFileName string, opts interface{}) error {
	buffer, err := loadAndSubstituteEnvs(configFileName)
	if err != nil {
		return err
	}

	// Generic interface for loading arbitrary yaml structure
	var intermediate map[string]interface{}

	if err := yaml.Unmarshal(buffer, &intermediate); err != nil {
		return fmt.Errorf("error unmarshalling config: %w", err)
	}

	return Decode(intermediate, opts)
}

func Decode(input interface{}, result interface{}) error {
	// Using mapstructure to decode arbitrary yaml structure into options and
	// merge with existing values instead of overwriting everything. This is especially
	// important as we have a lot of default values for boolean which are supposed to be
	// true by default. Normally by just parsing through yaml all booleans that aren't
	// referenced in the config file would be parsed as false and we cannot identify after
	// the fact if they have been explicitly set to false or have not been referenced.
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:           mapstructure.ComposeDecodeHookFunc(toDurationHookFunc()),
		Metadata:             nil,    // Don't track any metadata
		Result:               result, // Decode the result into the prefilled options
		TagName:              "json", // Parse all fields that use the yaml tag
		ZeroFields:           false,  // Don't clean the default values from the result map (options)
		ErrorUnused:          true,   // Throw an error if keys have been used that aren't mapped to any struct fields
		IgnoreUntaggedFields: true,   // Ignore fields in structures that aren't tagged with yaml
	})

	if err != nil {
		return fmt.Errorf("error creating decoder for config: %w", err)
	}

	if err := decoder.Decode(input); err != nil {
		return fmt.Errorf("error decoding config: %w", err)
	}

	return nil
}

// Load yaml file into byte buffer and substitute envs references
func loadAndSubstituteEnvs(configFileName string) ([]byte, error) {
	if configFileName == "" {
		return nil, errors.New("no configuration file provided")
	}

	unparsedBuffer, err := os.ReadFile(configFileName)
	if err != nil {
		return nil, fmt.Errorf("unable to load config file: %w", err)
	}

	// We now parse over the yaml with env substring, and fill in the ENV's
	buffer, err := envsubst.Bytes(unparsedBuffer)
	if err != nil {
		return nil, fmt.Errorf("error in substituting env variables : %w", err)
	}

	return buffer, nil

}

// registerFlags uses `cfg` and `flag` tags to associate flags in the flagSet
// to the fields in the options interface provided.
// Each exported field in the options must have a `cfg` tag otherwise an error will occur.
// - For fields, set `cfg` and `flag` so that `flag` is the name of the flag associated to this config option
// - For exported fields that are not user facing, set the `cfg` to `,internal`
// - For structs containing user facing fields, set the `cfg` to `,squash`
func registerFlags(v *viper.Viper, prefix string, flagSet *pflag.FlagSet, options interface{}) error {
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
		//    cfg - the name of the config file option
		field := typ.Field(i)
		fieldV := reflect.Indirect(val).Field(i)
		fieldName := strings.Join([]string{prefix, field.Name}, ".")

		cfgName := field.Tag.Get("cfg")
		if cfgName == ",internal" {
			// Public but internal types that should not be exposed to users, skip them
			continue
		}

		if isUnexported(field.Name) {
			// Unexported fields cannot be set by a user, so won't have tags or flags, skip them
			continue
		}

		if field.Type.Kind() == reflect.Struct {
			if cfgName != ",squash" {
				return fmt.Errorf("field %q does not have required cfg tag: `,squash`", fieldName)
			}
			err := registerFlags(v, fieldName, flagSet, fieldV.Interface())
			if err != nil {
				return err
			}
			continue
		}

		flagName := field.Tag.Get("flag")
		if flagName == "" || cfgName == "" {
			return fmt.Errorf("field %q does not have required tags (cfg, flag)", fieldName)
		}

		if flagSet == nil {
			return fmt.Errorf("flagset cannot be nil")
		}

		f := flagSet.Lookup(flagName)
		if f == nil {
			return fmt.Errorf("field %q does not have a registered flag", flagName)
		}
		err := v.BindPFlag(cfgName, f)
		if err != nil {
			return fmt.Errorf("error binding flag for field %q: %w", fieldName, err)
		}
	}

	return nil
}

// decodeFromCfgTag sets the Viper decoder to read the names from the `cfg` tag
// on each struct entry.
func decodeFromCfgTag(c *mapstructure.DecoderConfig) {
	c.TagName = "cfg"
}

// isUnexported checks if a field name starts with a lowercase letter and therefore
// if it is unexported.
func isUnexported(name string) bool {
	if len(name) == 0 {
		// This should never happen
		panic("field name has len 0")
	}

	first := string(name[0])
	return first == strings.ToLower(first)
}
