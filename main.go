package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/mreiferson/go-options"
)

func main() {
	flagSet := flag.NewFlagSet("google_auth_proxy", flag.ExitOnError)

	googleAppsDomains := StringArray{}
	upstreams := StringArray{}
	skipAuthRegex := StringArray{}

	config := flagSet.String("config", "", "path to config file")
	showVersion := flagSet.Bool("version", false, "print version string")

	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("redirect-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\"")
	flagSet.Var(&upstreams, "upstream", "the http url(s) of the upstream endpoint. If multiple, routing is based on path")
	flagSet.Bool("pass-basic-auth", true, "pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-access-token", false, "pass OAuth access_token to upstream via X-Forwarded-Access-Token header")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Var(&skipAuthRegex, "skip-auth-regex", "bypass authentication for requests path's that match (may be given multiple times)")

	flagSet.Var(&googleAppsDomains, "google-apps-domain", "authenticate against the given Google apps domain (may be given multiple times)")
	flagSet.String("client-id", "", "the Google OAuth Client ID: ie: \"123456.apps.googleusercontent.com\"")
	flagSet.String("client-secret", "", "the OAuth Client Secret")
	flagSet.String("authenticated-emails-file", "", "authenticate against emails via file (one per line)")
	flagSet.String("htpasswd-file", "", "additionally authenticate against a htpasswd file. Entries must be created with \"htpasswd -s\" for SHA encryption")
	flagSet.Bool("display-htpasswd-form", true, "display username / password login form if an htpasswd file is provided")
	flagSet.String("custom-templates-dir", "", "path to custom html templates")

	flagSet.String("cookie-secret", "", "the seed string for secure cookies")
	flagSet.String("cookie-domain", "", "an optional cookie domain to force cookies to (ie: .yourcompany.com)*")
	flagSet.Duration("cookie-expire", time.Duration(168)*time.Hour, "expire timeframe for cookie")
	flagSet.Bool("cookie-https-only", true, "set secure (HTTPS) cookies (deprecated. use --cookie-secure setting)")
	flagSet.Bool("cookie-secure", true, "set secure (HTTPS) cookie flag")
	flagSet.Bool("cookie-httponly", true, "set HttpOnly cookie flag")

	flagSet.Bool("request-logging", true, "Log requests to stdout")

	flagSet.String("provider", "", "Oauth provider (defaults to Google)")
	flagSet.String("login-url", "", "Authentication endpoint")
	flagSet.String("redeem-url", "", "Token redemption endpoint")
	flagSet.String("profile-url", "", "Profile access endpoint")
	flagSet.String("scope", "", "Oauth scope specification")

	flagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("google_auth_proxy v%s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	opts := NewOptions()

	cfg := make(EnvOptions)
	if *config != "" {
		_, err := toml.DecodeFile(*config, &cfg)
		if err != nil {
			log.Fatalf("ERROR: failed to load config file %s - %s", *config, err)
		}
	}
	cfg.LoadEnvForStruct(opts)
	options.Resolve(opts, flagSet, cfg)

	err := opts.Validate()
	if err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}

	validator := NewValidator(opts.GoogleAppsDomains, opts.AuthenticatedEmailsFile)
	oauthproxy := NewOauthProxy(opts, validator)

	if len(opts.GoogleAppsDomains) != 0 && opts.AuthenticatedEmailsFile == "" {
		if len(opts.GoogleAppsDomains) > 1 {
			oauthproxy.SignInMessage = fmt.Sprintf("Authenticate using one of the following domains: %v", strings.Join(opts.GoogleAppsDomains, ", "))
		} else {
			oauthproxy.SignInMessage = fmt.Sprintf("Authenticate using %v", opts.GoogleAppsDomains[0])
		}
	}

	if opts.HtpasswdFile != "" {
		log.Printf("using htpasswd file %s", opts.HtpasswdFile)
		oauthproxy.HtpasswdFile, err = NewHtpasswdFromFile(opts.HtpasswdFile)
		oauthproxy.DisplayHtpasswdForm = opts.DisplayHtpasswdForm
		if err != nil {
			log.Fatalf("FATAL: unable to open %s %s", opts.HtpasswdFile, err)
		}
	}

	u, err := url.Parse(opts.HttpAddress)
	if err != nil {
		log.Fatalf("FATAL: could not parse %#v: %v", opts.HttpAddress, err)
	}

	var networkType string
	switch u.Scheme {
	case "", "http":
		networkType = "tcp"
	default:
		networkType = u.Scheme
	}
	listenAddr := strings.TrimPrefix(u.String(), u.Scheme+"://")

	listener, err := net.Listen(networkType, listenAddr)
	if err != nil {
		log.Fatalf("FATAL: listen (%s, %s) failed - %s", networkType, listenAddr, err)
	}
	log.Printf("listening on %s", listenAddr)

	server := &http.Server{Handler: LoggingHandler(os.Stdout, oauthproxy, opts.RequestLogging)}
	err = server.Serve(listener)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("ERROR: http.Serve() - %s", err)
	}

	log.Printf("HTTP: closing %s", listener.Addr())
}
