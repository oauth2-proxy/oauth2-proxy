package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/bitly/go-simplejson"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const signInPath = "/oauth2/sign_in"
const oauthStartPath = "/oauth2/start"
const oauthCallbackPath = "/oauth2/callback"

type OauthProxy struct {
	CookieSeed string
	CookieKey  string
	Validator  func(string) bool

	redirectUrl        *url.URL // the url to receive requests at
	oauthRedemptionUrl *url.URL // endpoint to redeem the code
	oauthLoginUrl      *url.URL // to redirect the user to
	oauthUserInfoUrl   *url.URL
	oauthScope         string
	clientID           string
	clientSecret       string
	SignInMessage      string
	HtpasswdFile       *HtpasswdFile
	serveMux           *http.ServeMux
}

func NewOauthProxy(proxyUrls []*url.URL, clientID string, clientSecret string, validator func(string) bool) *OauthProxy {
	login, _ := url.Parse("https://accounts.google.com/o/oauth2/auth")
	redeem, _ := url.Parse("https://accounts.google.com/o/oauth2/token")
	info, _ := url.Parse("https://www.googleapis.com/oauth2/v2/userinfo")
	serveMux := http.NewServeMux()
	for _, u := range proxyUrls {
		path := u.Path
		u.Path = ""
		log.Printf("mapping %s => %s", path, u)
		serveMux.Handle(path, httputil.NewSingleHostReverseProxy(u))
	}
	return &OauthProxy{
		CookieKey:  "_oauthproxy",
		CookieSeed: *cookieSecret,
		Validator:  validator,

		clientID:           clientID,
		clientSecret:       clientSecret,
		oauthScope:         "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
		oauthRedemptionUrl: redeem,
		oauthLoginUrl:      login,
		oauthUserInfoUrl:   info,
		serveMux:           serveMux,
	}
}

func (p *OauthProxy) SetRedirectUrl(redirectUrl *url.URL) {
	redirectUrl.Path = oauthCallbackPath
	p.redirectUrl = redirectUrl
}

func (p *OauthProxy) GetLoginURL() string {
	params := url.Values{}
	params.Add("redirect_uri", p.redirectUrl.String())
	params.Add("approval_prompt", "force")
	params.Add("scope", p.oauthScope)
	params.Add("client_id", p.clientID)
	params.Add("response_type", "code")
	return fmt.Sprintf("%s?%s", p.oauthLoginUrl, params.Encode())
}

func apiRequest(req *http.Request) (*simplejson.Json, error) {
	httpclient := &http.Client{}
	resp, err := httpclient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		log.Printf("got response code %d - %s", resp.StatusCode, body)
		return nil, errors.New("api request returned 200 status code")
	}
	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (p *OauthProxy) redeemCode(code string) (string, error) {
	params := url.Values{}
	params.Add("redirect_uri", p.redirectUrl.String())
	params.Add("client_id", p.clientID)
	params.Add("client_secret", p.clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	log.Printf("body is %s", params.Encode())
	req, err := http.NewRequest("POST", p.oauthRedemptionUrl.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		log.Printf("failed building request %s", err.Error())
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	json, err := apiRequest(req)
	if err != nil {
		log.Printf("failed making request %s", err.Error())
		return "", err
	}
	access_token, err := json.Get("access_token").String()
	if err != nil {
		return "", err
	}
	return access_token, nil
}

func (p *OauthProxy) getUserInfo(token string) (string, error) {
	params := url.Values{}
	params.Add("access_token", token)
	endpoint := fmt.Sprintf("%s?%s", p.oauthUserInfoUrl.String(), params.Encode())
	log.Printf("calling %s", endpoint)
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Printf("failed building request %s", err.Error())
		return "", err
	}
	json, err := apiRequest(req)
	if err != nil {
		log.Printf("failed making request %s", err.Error())
		return "", err
	}
	email, err := json.Get("email").String()
	if err != nil {
		log.Printf("failed getting email from response %s", err.Error())
		return "", err
	}
	return email, nil
}

func ClearCookie(rw http.ResponseWriter, req *http.Request, key string) {
	domain := strings.Split(req.Host, ":")[0]
	if *cookieDomain != "" {
		domain = *cookieDomain
	}
	cookie := &http.Cookie{
		Name:     key,
		Value:    "",
		Path:     "/",
		Domain:   domain,
		Expires:  time.Now().Add(time.Duration(1) * time.Hour * -1),
		HttpOnly: true,
	}
	http.SetCookie(rw, cookie)
}

func (p *OauthProxy) ErrorPage(rw http.ResponseWriter, code int, title string, message string) {
	log.Printf("ErrorPage %d %s %s", code, title, message)
	rw.WriteHeader(code)
	templates := getTemplates()
	t := struct {
		Title         string
		Message       string
	}{
		Title:         fmt.Sprintf("%d %s", code, title),
		Message:       message,
	}
	templates.ExecuteTemplate(rw, "error.html", t)
}

func (p *OauthProxy) SignInPage(rw http.ResponseWriter, req *http.Request, code int) {
	// TODO: capture state for which url to redirect to at the end
	rw.WriteHeader(code)
	templates := getTemplates()
	t := struct{ SignInMessage string }{SignInMessage: p.SignInMessage}
	templates.ExecuteTemplate(rw, "sign_in.html", t)
}

func (p *OauthProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// check if this is a redirect back at the end of oauth
	if req.URL.Path == signInPath {
		ClearCookie(rw, req, p.CookieKey)
		p.SignInPage(rw, req, 200)
		return
	}
	if req.URL.Path == oauthStartPath {
		http.Redirect(rw, req, p.GetLoginURL(), 302)
		return
	}
	if req.URL.Path == oauthCallbackPath {
		// finish the oauth cycle
		reqParams, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			p.ErrorPage(rw, 500, "Internal Error", err.Error())
			return
		}
		errorString, ok := reqParams["error"]
		if ok && len(errorString) == 1 {
			p.ErrorPage(rw, 403, "Permission Denied", errorString[0])
			return
		}
		code, ok := reqParams["code"]
		if !ok || len(code) != 1 {
			p.ErrorPage(rw, 500, "Internal Error", "Invalid API response")
			return
		}

		token, err := p.redeemCode(code[0])
		if err != nil {
			log.Printf("error redeeming code %s", err.Error())
			p.ErrorPage(rw, 500, "Internal Error", err.Error())
			return
		}
		// validate user
		email, err := p.getUserInfo(token)
		if err != nil {
			log.Printf("error redeeming code %s", err.Error())
			p.ErrorPage(rw, 500, "Internal Error", err.Error())
			return
		}

		// set cookie, or deny
		if p.Validator(email) {
			log.Printf("authenticating %s completed", email)
			domain := strings.Split(req.Host, ":")[0]
			if *cookieDomain != "" {
				domain = *cookieDomain
			}

			cookie := &http.Cookie{
				Name:     p.CookieKey,
				Value:    signedCookieValue(p.CookieSeed, p.CookieKey, email),
				Path:     "/",
				Domain:   domain,
				Expires:  time.Now().Add(time.Duration(168) * time.Hour), // 7 days
				HttpOnly: true,
				// Secure: req. ... ? set if X-Scheme: https ?
			}
			http.SetCookie(rw, cookie)
			http.Redirect(rw, req, "/", 302)
			return
		} else {
			p.ErrorPage(rw, 403, "Permission Denied", "Invalid Account")
			return
		}
	}
	
	cookie, err := req.Cookie(p.CookieKey)
	var ok bool
	var email string
	var user string
	if err == nil {
		email, ok = validateCookie(cookie, p.CookieSeed)
		user = strings.Split(email, "@")[0]
	}

	if !ok {
		user, ok = p.CheckBasicAuth(req)
	}

	if !ok {
		log.Printf("invalid cookie")
		p.SignInPage(rw, req, 403)
		return
	}

	// At this point, the user is authenticated. proxy normally
	if *passBasicAuth {
		req.SetBasicAuth(user, "")
		req.Header["X-Forwarded-User"] = []string{user}
	}

	p.serveMux.ServeHTTP(rw, req)
}

func (p *OauthProxy) CheckBasicAuth(req *http.Request) (string, bool) {
	if p.HtpasswdFile == nil {
		return "", false
	}
	s := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return "", false
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return "", false
	}
	if p.HtpasswdFile.Validate(pair[0], pair[1]) {
		return pair[0], true
	}
	return "", false
}
