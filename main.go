package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const VERSION = "0.1.0"

var (
	showVersion             = flag.Bool("version", false, "print version string")
	httpAddr                = flag.String("http-address", "127.0.0.1:4180", "<addr>:<port> to listen on for HTTP clients")
	redirectUrl             = flag.String("redirect-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\"")
	clientID                = flag.String("client-id", "", "the Google OAuth Client ID: ie: \"123456.apps.googleusercontent.com\"")
	clientSecret            = flag.String("client-secret", "", "the OAuth Client Secret")
	passBasicAuth           = flag.Bool("pass-basic-auth", true, "pass HTTP Basic Auth information to upstream")
	htpasswdFile            = flag.String("htpasswd-file", "", "additionally authenticate against a htpasswd file. Entries must be created with \"htpasswd -s\" for SHA encryption")
	cookieSecret            = flag.String("cookie-secret", "", "the seed string for secure cookies")
	cookieDomain            = flag.String("cookie-domain", "", "an optional cookie domain to force cookies to")
	authenticatedEmailsFile = flag.String("authenticated-emails-file", "", "authenticate against emails via file (one per line)")
	googleAppsDomains       = StringArray{}
	upstreams               = StringArray{}
)

func init() {
	flag.Var(&googleAppsDomains, "google-apps-domain", "authenticate against the given google apps domain (may be given multiple times)")
	flag.Var(&upstreams, "upstream", "the http url(s) of the upstream endpoint. If multiple, routing is based on path")
}

func main() {

	flag.Parse()

	// Try to use env for secrets if no flag is set
	if *clientID == "" {
		*clientID = os.Getenv("google_auth_client_id")
	}
	if *clientSecret == "" {
		*clientSecret = os.Getenv("google_auth_secret")
	}
	if *cookieSecret == "" {
		*cookieSecret = os.Getenv("google_auth_cookie_secret")
	}

	if *showVersion {
		fmt.Printf("google_auth_proxy v%s\n", VERSION)
		return
	}

	if len(upstreams) < 1 {
		log.Fatal("missing --upstream")
	}
	if *cookieSecret == "" {
		log.Fatal("missing --cookie-secret")
	}
	if *clientID == "" {
		log.Fatal("missing --client-id")
	}
	if *clientSecret == "" {
		log.Fatal("missing --client-secret")
	}

	var upstreamUrls []*url.URL
	for _, u := range upstreams {
		upstreamUrl, err := url.Parse(u)
		if err != nil {
			log.Fatalf("error parsing --upstream %s", err.Error())
		}
		upstreamUrls = append(upstreamUrls, upstreamUrl)
	}
	redirectUrl, err := url.Parse(*redirectUrl)
	if err != nil {
		log.Fatalf("error parsing --redirect-url %s", err.Error())
	}

	validator := NewValidator(googleAppsDomains, *authenticatedEmailsFile)
	oauthproxy := NewOauthProxy(upstreamUrls, *clientID, *clientSecret, validator)
	oauthproxy.SetRedirectUrl(redirectUrl)
	if len(googleAppsDomains) != 0 && *authenticatedEmailsFile == "" {
		oauthproxy.SignInMessage = fmt.Sprintf("using a email address from the following domains: %v", strings.Join(googleAppsDomains, ", "))
	}
	if *htpasswdFile != "" {
		oauthproxy.HtpasswdFile, err = NewHtpasswdFromFile(*htpasswdFile)
		if err != nil {
			log.Fatalf("FATAL: unable to open %s %s", *htpasswdFile, err.Error())
		}
	}
	listener, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		log.Fatalf("FATAL: listen (%s) failed - %s", *httpAddr, err.Error())
	}
	log.Printf("listening on %s", *httpAddr)

	server := &http.Server{Handler: oauthproxy}
	err = server.Serve(listener)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("ERROR: http.Serve() - %s", err.Error())
	}

	log.Printf("HTTP: closing %s", listener.Addr().String())
}
