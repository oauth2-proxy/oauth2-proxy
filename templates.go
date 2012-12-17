package main

import (
	"html/template"
	"log"
)

func getTemplates() *template.Template {
	t, err := template.New("foo").Parse(`{{define "sign_in.html"}}
<html><head><title>Sign In</title></head>
	<body>
	<form method="GET" action="/oauth2/start">
	<button type="submit">Sign In w/ Google</button>
	{{.SignInMessage}}
	</form>
</body></html>
{{end}}`)
	if err != nil {
		log.Fatalf("failed parsing template %s", err.Error())
	}
	
	t, err = t.Parse(`{{define "error.html"}}
<html><head><title>{{.Title}}</title></head>
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
