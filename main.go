package main

import (
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
)

func main() {
	logger.SetFlags(logger.Lshortfile)
	flagSet := options.NewFlagSet()

	config := flagSet.String("config", "", "path to config file")
	showVersion := flagSet.Bool("version", false, "print version string")

	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		logger.Printf("ERROR: Failed to parse flags: %v", err)
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("oauth2-proxy %s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	legacyOpts := options.NewLegacyOptions()
	err = options.Load(*config, flagSet, legacyOpts)
	if err != nil {
		logger.Errorf("ERROR: Failed to load config: %v", err)
		os.Exit(1)
	}

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		logger.Errorf("ERROR: Failed to convert config: %v", err)
		os.Exit(1)
	}

	err = validation.Validate(opts)
	if err != nil {
		logger.Printf("%s", err)
		os.Exit(1)
	}

	validator := NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile)
	oauthproxy, err := NewOAuthProxy(opts, validator)
	if err != nil {
		logger.Errorf("ERROR: Failed to initialise OAuth2 Proxy: %v", err)
		os.Exit(1)
	}

	rand.Seed(time.Now().UnixNano())

	s := &Server{
		Handler: oauthproxy,
		Opts:    opts,
		stop:    make(chan struct{}, 1),
	}
	// Observe signals in background goroutine.
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint
		s.stop <- struct{}{} // notify having caught signal
	}()
	s.ListenAndServe()
}
