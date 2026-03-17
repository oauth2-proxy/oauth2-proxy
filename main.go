package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/healthcheck"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/version"
	"github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"
)

func main() {
	logger.SetFlags(logger.Lshortfile)

	// Check if "health" subcommand is being invoked (e.g., "oauth2-proxy health")
	if len(os.Args) > 1 && os.Args[1] == "health" {
		runHealthCheck(os.Args[2:])
		return
	}

	configFlagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ContinueOnError)

	// Because we parse early to determine alpha vs legacy config, we have to
	// ignore any unknown flags for now
	configFlagSet.ParseErrorsAllowlist.UnknownFlags = true

	config := configFlagSet.String("config", "", "path to config file")
	alphaConfig := configFlagSet.String("alpha-config", "", "path to alpha config file (use at your own risk - the structure in this config file may change between minor releases)")
	convertConfig := configFlagSet.Bool("convert-config-to-alpha", false, "if true, the proxy will load configuration as normal and convert existing configuration to the alpha config structure, and print it to stdout")
	showVersion := configFlagSet.Bool("version", false, "print version string")
	checkHealth := configFlagSet.Bool("healthcheck", false, "perform a health check against a running oauth2-proxy instance and exit")
	configFlagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2-proxy %s (built with %s)\n", version.VERSION, runtime.Version())
		return
	}

	if *checkHealth {
		runHealthCheckFromConfig(*config, *alphaConfig, configFlagSet, os.Args[1:])
		return
	}

	if *convertConfig && *alphaConfig != "" {
		logger.Fatal("cannot use alpha-config and convert-config-to-alpha together")
	}

	opts, err := loadConfiguration(*config, *alphaConfig, configFlagSet, os.Args[1:])
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

	validator := NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile)
	oauthproxy, err := NewOAuthProxy(opts, validator)
	if err != nil {
		logger.Fatalf("ERROR: Failed to initialise OAuth2 Proxy: %v", err)
	}

	if err := oauthproxy.Start(); err != nil {
		logger.Fatalf("ERROR: Failed to start OAuth2 Proxy: %v", err)
	}
}

// runHealthCheck handles the "health" subcommand with its own flag set.
func runHealthCheck(args []string) {
	fs := pflag.NewFlagSet("health", pflag.ContinueOnError)
	httpAddr := fs.String("http-address", healthcheck.DefaultHTTPAddress, "HTTP address of the oauth2-proxy instance to check")
	httpsAddr := fs.String("https-address", "", "HTTPS address of the oauth2-proxy instance to check")
	pingPath := fs.String("ping-path", healthcheck.DefaultPingPath, "path of the ping endpoint")
	timeout := fs.Duration("timeout", healthcheck.DefaultTimeout, "timeout for the health check request")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS certificate verification for HTTPS health checks")

	if err := fs.Parse(args); err != nil {
		logger.Fatalf("ERROR: %v", err)
	}

	opts := healthcheck.CheckOptions{
		HTTPAddress:        *httpAddr,
		HTTPSAddress:       *httpsAddr,
		PingPath:           *pingPath,
		Timeout:            *timeout,
		InsecureSkipVerify: *insecure,
	}

	if err := healthcheck.Run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("OK")
}

// runHealthCheckFromConfig performs a health check using the loaded configuration.
// This supports the --healthcheck flag which respects the same configuration as the proxy.
func runHealthCheckFromConfig(config, alphaConfig string, extraFlags *pflag.FlagSet, args []string) {
	opts, err := loadConfiguration(config, alphaConfig, extraFlags, args)
	if err != nil {
		// If config loading fails, fall back to defaults
		logger.Printf("WARNING: failed to load configuration: %v; using defaults", err)
		checkOpts := healthcheck.DefaultCheckOptions()
		if err := healthcheck.Run(checkOpts); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")
		return
	}

	checkOpts := healthcheck.CheckOptions{
		HTTPAddress:  opts.Server.BindAddress,
		HTTPSAddress: opts.Server.SecureBindAddress,
		PingPath:     opts.PingPath,
		Timeout:      5 * time.Second,
	}

	if err := healthcheck.Run(checkOpts); err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("OK")
}

// loadConfiguration will load in the user's configuration.
// It will either load the alpha configuration (if alphaConfig is given)
// or the legacy configuration.
func loadConfiguration(config, yamlConfig string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	opts, err := loadLegacyOptions(config, extraFlags, args)
	if err != nil {
		return nil, fmt.Errorf("failed to load legacy options: %w", err)
	}

	if yamlConfig != "" {
		logger.Printf("WARNING: You are using alpha configuration. The structure in this configuration file may change without notice. You MUST remove conflicting options from your existing configuration.")
		opts, err = loadYamlOptions(yamlConfig, config, extraFlags, args)
		if err != nil {
			return nil, fmt.Errorf("failed to load yaml options: %w", err)
		}
	}

	// Ensure defaults after loading configuration
	opts.EnsureDefaults()
	return opts, nil
}

// loadLegacyOptions loads the old toml options using the legacy flagset
// and legacy options struct.
func loadLegacyOptions(config string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	optionsFlagSet := options.NewLegacyFlagSet()
	optionsFlagSet.AddFlagSet(extraFlags)
	if err := optionsFlagSet.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %v", err)
	}

	legacyOpts := options.NewLegacyOptions()
	if err := options.Load(config, optionsFlagSet, legacyOpts); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to convert config: %v", err)
	}

	return opts, nil
}

// loadYamlOptions loads the old style config excluding options converted to
// the new alpha format, then merges the alpha options, loaded from YAML,
// into the core configuration.
func loadYamlOptions(yamlConfig, config string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	opts, err := loadOptions(config, extraFlags, args)
	if err != nil {
		return nil, fmt.Errorf("failed to load core options: %v", err)
	}

	alphaOpts := options.NewAlphaOptions(opts)
	if err := options.LoadYAML(yamlConfig, alphaOpts); err != nil {
		return nil, fmt.Errorf("failed to load alpha options: %v", err)
	}

	alphaOpts.MergeOptionsWithDefaults(opts)
	return opts, nil
}

// loadOptions loads the configuration using the old style format into the
// core options.Options struct.
// This means that none of the options that have been converted to alpha config
// will be loaded using this method.
func loadOptions(config string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	optionsFlagSet := options.NewFlagSet()
	optionsFlagSet.AddFlagSet(extraFlags)
	if err := optionsFlagSet.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %v", err)
	}

	opts := options.NewOptions()
	if err := options.Load(config, optionsFlagSet, opts); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	return opts, nil
}

// printConvertedConfig extracts alpha options from the loaded configuration
// and renders these to stdout in YAML format.
func printConvertedConfig(opts *options.Options) error {
	alphaConfig := options.NewAlphaOptions(opts)

	// Generic interface for loading arbitrary yaml structure
	var buffer map[string]interface{}

	if err := options.Decode(alphaConfig, &buffer); err != nil {
		return fmt.Errorf("unable to decode alpha config into interface: %w", err)
	}

	data, err := yaml.Marshal(buffer)
	if err != nil {
		return fmt.Errorf("unable to marshal config: %v", err)
	}

	if _, err := os.Stdout.Write(data); err != nil {
		return fmt.Errorf("unable to write output: %v", err)
	}

	return nil
}
