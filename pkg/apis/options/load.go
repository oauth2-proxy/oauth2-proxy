package options

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
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

// LoadYAML will load a YAML based configuration file into the options interface provided.
func LoadYAML(configFileName string, into interface{}) error {
	buffer, err := loadAndParseYaml(configFileName)
	if err != nil {
		return err
	}

	// UnmarshalStrict will return an error if the config includes options that are
	// not mapped to fields of the into struct
	if err := yaml.UnmarshalStrict(buffer, into, yaml.DisallowUnknownFields); err != nil {
		return fmt.Errorf("error unmarshalling config: %w", err)
	}

	return nil
}

// Performs the heavy lifting of the LoadYaml function
func loadAndParseYaml(configFileName string) ([]byte, error) {
	if configFileName == "" {
		return nil, errors.New("no configuration file provided")
	}

	unparsedBuffer, err := os.ReadFile(configFileName)
	if err != nil {
		return nil, fmt.Errorf("unable to load config file: %w", err)
	}

	modifiedBuffer, err := normalizeSubstitution(unparsedBuffer, err)
	if err != nil {
		return nil, fmt.Errorf("error normalizing substitution string : %w", err)
	}

	// We now parse over the yaml with env substring, and fill in the ENV's
	buffer, err := envsubst.Bytes(modifiedBuffer)
	if err != nil {
		return nil, fmt.Errorf("error in substituting env variables : %w", err)
	}

	return buffer, nil
}

func normalizeSubstitution(unparsedBuffer []byte, err error) ([]byte, error) {
	// Convert the byte array to a string for regex processing
	unparsedString := string(unparsedBuffer)

	// Compile the regex pattern
	regexPattern, err := regexp.Compile(`\$(\d+)`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	substitutedString := regexPattern.ReplaceAllString(unparsedString, `$$$$1`)

	modifiedBuffer := []byte(substitutedString)
	return modifiedBuffer, nil
}
