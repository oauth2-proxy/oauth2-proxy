package main

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"time"

	"github.com/ghodss/yaml"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/spf13/pflag"
)

func main() {
	logger.SetFlags(logger.Lshortfile)

	configFlagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ContinueOnError)

	// Because we parse early to determine config vs legacy config, we have to
	// ignore any unknown flags for now
	configFlagSet.ParseErrorsWhitelist.UnknownFlags = true

	config := configFlagSet.String("config", "", "path to config file")
	legacyConfig := configFlagSet.String("legacy-config", "", "path to legacy config file")
	convertConfig := configFlagSet.Bool("convert-legacy-config", true, "If true, the legacy toml configuration will be converted to the new yaml config structure, and print it to stdout")
	showVersion := configFlagSet.Bool("version", false, "print version string")
	configFlagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2-proxy %s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	if *config != "" && *legacyConfig != "" {
		logger.Fatal("cannot use config and legacy-config together. either continue using the legacy-config or convert it to the new config structure using convert-legacy-config.")
	}

	if *convertConfig && *config != "" {
		logger.Fatal("cannot use convert-legacy-config together with config or legacy-config.")
	}

	opts, err := loadConfiguration(*config, *legacyConfig, configFlagSet, os.Args[1:])
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

	rand.Seed(time.Now().UnixNano())

	if err := oauthproxy.Start(); err != nil {
		logger.Fatalf("ERROR: Failed to start OAuth2 Proxy: %v", err)
	}
}

// loadConfiguration will load in the user's configuration.
// It will either load the yaml configuration or the legacy configuration.
func loadConfiguration(config, legacyConfig string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	if legacyConfig != "" {
		logger.Printf("WARNING: You are still using the legacy configuration. This configuration has been deprecated and will be removed in a future release. Please consider converting to the new configuration format.")
		return loadLegacyOptions(legacyConfig, extraFlags, args)
	}
	return loadYamlOptions(config)
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

// loadYamlOptions loads the old style config excluding options converted to
// the new structured format, then merges the structured options, loaded from YAML,
// into the core configuration.
func loadYamlOptions(configFile string) (*options.Options, error) {
	yamlOpts := &options.YamlOptions{}
	if err := options.LoadYAML(configFile, yamlOpts); err != nil {
		return nil, fmt.Errorf("failed to load yaml options: %v", err)
	}

	opts := options.NewOptions()
	yamlOpts.MergeInto(opts)
	return opts, nil
}

// printConvertedConfig extracts yaml options from the loaded configuration
// and renders these to stdout in YAML format.
func printConvertedConfig(opts *options.Options) error {
	yamlConfig := &options.YamlOptions{}
	yamlConfig.ExtractFrom(opts)

	data, err := yaml.Marshal(yamlConfig)
	if err != nil {
		return fmt.Errorf("unable to marshal config: %v", err)
	}

	if _, err := os.Stdout.Write(data); err != nil {
		return fmt.Errorf("unable to write output: %v", err)
	}

	return nil
}
