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
./google_auth_proxy
  -client-id="": the Google OAuth Client ID: ie: "123456.apps.googleusercontent.com"
  -client-secret="": the OAuth Client secret
  -cookie-secret="": the seed for cookie values
  -redirect-url="": the http base to redirect to. ie: https://internalapp.yourcompany.com/oauth2/callback
  -htpasswd-file="": additionally lookup basic auth in a htpasswd file. Entries must be created with "htpasswd -s" for SHA encryption
  -pass-basic-auth=true: pass basic auth information to upstream
  -upstream=[]: the http url(s) of the upstream endpoint(s). If multiple, routing is based on URL path
```