google_auth_proxy
=================

A reverse proxy that acts as an authentication layer using Google Oauth2 to validate 
individual accounts, or a whole google apps domain.


## Structure


```
    _______       ___________________       __________
    |Nginx| ----> |google_auth_proxy| ----> |upstream| 
    -------       -------------------       ----------
                          ||
                          \/
                  [google oauth2 api]

```

## Configuration
    
1) visit to Google Api Console https://code.google.com/apis/console/
2) under "API Access", choose "Create an OAuth 2.0 Client ID"
3) Edit the application settings, and list the Redirect URI(s) where you will run your application. For example: 
`https://internalapp.yourcompany.com/oauth2/callback`

## Usage

```
Usage of ./google_auth_proxy:
  -authenticated-emails-file="": authenticate against emails via file (one per line)
  -client-id="": the Google OAuth Client ID: ie: "123456.apps.googleusercontent.com"
  -client-secret="": the OAuth Client Secret
  -cookie-domain="": an optional cookie domain to force cookies to
  -cookie-secret="": the seed string for secure cookies
  -google-apps-domain="": authenticate against the given google apps domain
  -htpasswd-file="": additionally authenticate against a htpasswd file. Entries must be created with "htpasswd -s" for SHA encryption
  -http-address="0.0.0.0:4180": <addr>:<port> to listen on for HTTP clients
  -pass-basic-auth=true: pass HTTP Basic Auth information to upstream
  -redirect-url="": the OAuth Redirect URL. ie: "https://internalapp.yourcompany.com/oauth2/callback"
  -upstream=[]: the http url(s) of the upstream endpoint. If multiple, routing is based on path
  -version=false: print version string
```

Unauthenticated requests will be redirected to `/oauth2/sign_in` to start the sign-in process.
