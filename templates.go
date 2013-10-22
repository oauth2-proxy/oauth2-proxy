package main

import (
	"html/template"
	"log"
)

func getTemplates() *template.Template {
	t, err := template.New("foo").Parse(`{{define "sign_in.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head><title>Sign In</title></head>
<body>
	<form method="GET" action="/oauth2/start">
	<input type="hidden" name="rd" value="{{.Redirect}}">
	<button type="submit">Sign In w/ Google</button>
	{{.SignInMessage}}
	</form>
	{{ if .Htpasswd }}
	<fieldset>
		<form method="POST" action="/oauth2/sign_in">
		<input type="hidden" name="rd" value="{{.Redirect}}">
		<label>Username: <input type="text" name="username" size="10"></label><br/>
		<label>Password: <input type="password" name="password" size="10"></label><br/>
		<button type="submit">Sign In</button>
		</form>
	</fieldset>
	{{ end }}
</body>
</html>
{{end}}`)
	if err != nil {
		log.Fatalf("failed parsing template %s", err.Error())
	}

	t, err = t.Parse(`{{define "error.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head><title>{{.Title}}</title></head>
<body>
	<h2>{{.Title}}</h2>
	<p>{{.Message}}</p>
	<hr>
	<p><a href="/oauth2/sign_in">Sign In</a></p>
</body>
</html>{{end}}`)
	if err != nil {
		log.Fatalf("failed parsing template %s", err.Error())
	}
	return t
}
