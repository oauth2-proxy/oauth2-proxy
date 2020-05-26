package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/validation"
)

func main() {
	logger.SetFlags(logger.Lshortfile)
	flagSet := options.NewFlagSet()

	config := flagSet.String("config", "", "path to config file")
	showVersion := flagSet.Bool("version", false, "print version string")

	flagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2-proxy %s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	opts := options.NewOptions()
	err := options.Load(*config, flagSet, opts)
	if err != nil {
		logger.Printf("ERROR: Failed to load config: %v", err)
		os.Exit(1)
	}

	err = validation.Validate(opts)
	if err != nil {
		logger.Printf("%s", err)
		os.Exit(1)
	}

	validator := NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile)
	oauthproxy := NewOAuthProxy(opts, validator)

	if len(opts.Banner) >= 1 {
		if opts.Banner == "-" {
			oauthproxy.SignInMessage = ""
		} else {
			oauthproxy.SignInMessage = opts.Banner
		}
	} else if len(opts.EmailDomains) != 0 && opts.AuthenticatedEmailsFile == "" {
		if len(opts.EmailDomains) > 1 {
			oauthproxy.SignInMessage = fmt.Sprintf("Authenticate using one of the following domains: %v", strings.Join(opts.EmailDomains, ", "))
		} else if opts.EmailDomains[0] != "*" {
			oauthproxy.SignInMessage = fmt.Sprintf("Authenticate using %v", opts.EmailDomains[0])
		}
	}

	if opts.HtpasswdFile != "" {
		logger.Printf("using htpasswd file %s", opts.HtpasswdFile)
		oauthproxy.HtpasswdFile, err = NewHtpasswdFromFile(opts.HtpasswdFile)
		oauthproxy.DisplayHtpasswdForm = opts.DisplayHtpasswdForm
		if err != nil {
			logger.Fatalf("FATAL: unable to open %s %s", opts.HtpasswdFile, err)
		}
	}

	rand.Seed(time.Now().UnixNano())

	var handler http.Handler
	if opts.GCPHealthChecks {
		handler = redirectToHTTPS(opts, gcpHealthcheck(LoggingHandler(oauthproxy)))
	} else {
		handler = redirectToHTTPS(opts, LoggingHandler(oauthproxy))
	}
	s := &Server{
		Handler: handler,
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
