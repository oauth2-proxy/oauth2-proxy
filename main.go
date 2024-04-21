package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/ghodss/yaml"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/spf13/pflag"
)

func main() {
	logger.SetFlags(logger.Lshortfile)

	configFlagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ContinueOnError)

	// Because we parse early to determine yaml vs legacy toml config, we have to
	// ignore any unknown flags for now
	configFlagSet.ParseErrorsWhitelist.UnknownFlags = true

	config := configFlagSet.String("config", "", "path to config file")
	yamlConfig := configFlagSet.String("yaml-config", "", "path to yaml config file (use at your own risk - the structure in this config file may change between minor releases)")
	convertConfig := configFlagSet.Bool("convert-config-to-yaml", false, "if true, the proxy will load configuration as normal and convert existing configuration to the yaml config structure, and print it to stdout")
	showVersion := configFlagSet.Bool("version", false, "print version string")
	configFlagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2-proxy %s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	if *convertConfig && *yamlConfig != "" {
		logger.Fatal("ERROR: cannot use yaml-config and convert-config-to-yaml together")
	}

	if *config != "" && *yamlConfig != "" {
		logger.Fatal("ERROR: cannot use config and yaml-config together anymore.\n" +
			"If you want to convert your legacy config and flags to the new format, use the convert-config-to-yaml flag.")
	}

	if *yamlConfig != "" && len(os.Args[1:]) > 2 {
		logger.Fatal("ERROR: cannot use yaml-config with other flags.\n" +
			"If you want to convert your legacy config and flags to the new format, use the convert-config-to-yaml flag.")
	}

	opts, err := loadConfiguration(*config, *yamlConfig, configFlagSet, os.Args[1:])
	if err != nil {
		logger.Fatalf("ERROR: %v", err)
	}

	if *convertConfig {
		if err := printConvertedConfig(opts); err != nil {
			logger.Fatalf("ERROR: could not convert config: %v", err)
		}
		return
	}

	if err = validation.Validate(opts); err != nil {
		logger.Fatalf("%s", err)
	}

	validator := NewValidator(opts.ProxyOptions.EmailDomains, opts.ProxyOptions.AuthenticatedEmailsFile)
	oauthproxy, err := NewOAuthProxy(opts, validator)
	if err != nil {
		logger.Fatalf("ERROR: Failed to initialise OAuth2 Proxy: %v", err)
	}

	if err := oauthproxy.Start(); err != nil {
		logger.Fatalf("ERROR: Failed to start OAuth2 Proxy: %v", err)
	}
}

// loadConfiguration will load in the user's configuration.
// It will either load the yaml configuration (if yamlConfig is given)
// or the legacy configuration.
func loadConfiguration(config, yamlConfig string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	if yamlConfig != "" {
		logger.Printf("WARNING: You are using yaml configuration. The structure in this configuration file may change without notice.")

		return loadYamlOptions(yamlConfig)
	}
	return loadLegacyOptions(config, extraFlags, args)
}

// loadLegacyOptions loads the old toml options using the legacy flagset
// and legacy options struct.
func loadLegacyOptions(legacyConfig string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	legacyFlagSet := options.NewLegacyFlagSet()
	legacyFlagSet.AddFlagSet(extraFlags)
	if err := legacyFlagSet.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %v", err)
	}

	legacyOpts := options.NewLegacyOptions()
	if err := options.Load(legacyConfig, legacyFlagSet, legacyOpts); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to convert config: %v", err)
	}

	return opts, nil
}

// loadYamlOptions loads all options using the new structured yaml format
func loadYamlOptions(yamlConfig string) (*options.Options, error) {
	opts := options.NewOptions()
	if err := options.LoadYAML(yamlConfig, opts); err != nil {
		return nil, fmt.Errorf("failed to load yaml options: %v", err)
	}

	return opts, nil
}

// printConvertedConfig extracts yaml options from the loaded configuration
// and renders these to stdout in YAML format.
func printConvertedConfig(opts *options.Options) error {
	data, err := yaml.Marshal(opts)
	if err != nil {
		return fmt.Errorf("unable to marshal config: %v", err)
	}

	if _, err := os.Stdout.Write(data); err != nil {
		return fmt.Errorf("unable to write output: %v", err)
	}

	return nil
}
