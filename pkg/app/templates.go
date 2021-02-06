package app

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

const (
	errorTemplateName  = "error.html"
	signInTemplateName = "sign_in.html"

	defaultErrorTemplate = `{{define "error.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  	<title>{{.StatusCode}} {{.Title}}</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.1/css/bulma.min.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.2/css/all.min.css">

  <script type="text/javascript">
    document.addEventListener('DOMContentLoaded', function() {
    	let cardToggles = document.getElementsByClassName('card-toggle');
    	for (let i = 0; i < cardToggles.length; i++) {
    		cardToggles[i].addEventListener('click', e => {
    			e.currentTarget.parentElement.parentElement.childNodes[3].classList.toggle('is-hidden');
    		});
    	}
    });
  </script>

  <style>
    body {
      height: 100vh;
    }
    .error-box {
      margin: 1.25rem auto;
      max-width: 600px;
    }
    .status-code {
      font-size: 12rem;
      font-weight: 600;
    }
    #more-info.card {
      border: 1px solid #f0f0f0;
    }
    footer a {
      text-decoration: underline;
    }
  </style>
</head>
<body class="has-background-light">
  <section class="section">
    <div class="box block error-box has-text-centered">
      <div class="status-code">{{.StatusCode}}</div>
      <div class="block">
        <h1 class="subtitle is-1">{{.Title}}</h1>
      </div>

      {{ if .Message }}
      <div id="more-info" class="block card is-fullwidth is-shadowless">
  			<header class="card-header is-shadowless">
  				<p class="card-header-title">More Info</p>
  				<a class="card-header-icon card-toggle">
  					<i class="fa fa-angle-down"></i>
  				</a>
  			</header>
  			<div class="card-content has-text-left is-hidden">
  				<div class="content">
  					{{.Message}}
  				</div>
  			</div>
  		</div>
      {{ end }}

      <hr>

      <div class="columns">
        <div class="column">
          <form method="GET" action="{{.Redirect}}">
            <button type="submit" class="button is-danger is-fullwidth">Go back</button>
          </form>
        </div>
        <div class="column">
          <form method="GET" action="{{.ProxyPrefix}}/sign_in">
            <input type="hidden" name="rd" value="{{.Redirect}}">
            <button type="submit" class="button is-primary is-fullwidth">Sign in</button>
          </form>
        </div>
      </div>

    </div>
  </section>

  <footer class="footer has-text-grey has-background-light is-size-7">
    <div class="content has-text-centered">
    	{{ if eq .Footer "-" }}
    	{{ else if eq .Footer ""}}
    	<p>Secured with <a href="https://github.com/oauth2-proxy/oauth2-proxy#oauth2_proxy" class="has-text-grey">OAuth2 Proxy</a> version {{.Version}}</p>
    	{{ else }}
    	<p>{{.Footer}}</p>
    	{{ end }}
    </div>
	</footer>

  </body>
</html>
{{end}}`

	defaultSignInTemplate = `{{define "sign_in.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <title>Sign In</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.1/css/bulma.min.css">

    <style>
      body {
        height: 100vh;
      }
      .sign-in-box {
        max-width: 400px;
        margin: 1.25rem auto;
      }
      footer a {
        text-decoration: underline;
      }
    </style>

    <script>
      if (window.location.hash) {
        (function() {
          var inputs = document.getElementsByName('rd');
          for (var i = 0; i < inputs.length; i++) {
            // Add hash, but make sure it is only added once
            var idx = inputs[i].value.indexOf('#');
            if (idx >= 0) {
              // Remove existing hash from URL
              inputs[i].value = inputs[i].value.substr(0, idx);
            }
            inputs[i].value += window.location.hash;
          }
        })();
      }
    </script>
  </head>
  <body class="has-background-light">
  <section class="section">
    <div class="box block sign-in-box has-text-centered">
      <form method="GET" action="{{.ProxyPrefix}}/start">
        <input type="hidden" name="rd" value="{{.Redirect}}">
          {{ if .SignInMessage }}
          <p class="block">{{.SignInMessage}}</p>
          {{ end}}
          <button type="submit" class="button block is-primary">Sign in with {{.ProviderName}}</button>
      </form>

      {{ if .CustomLogin }}
      <hr>

      <form method="POST" action="{{.ProxyPrefix}}/sign_in" class="block">
        <input type="hidden" name="rd" value="{{.Redirect}}">

        <div class="field">
          <label class="label" for="username">Username</label>
          <div class="control">
            <input class="input" type="email" placeholder="e.g. userx@example.com"  name="username" id="username">
          </div>
        </div>

        <div class="field">
          <label class="label" for="password">Password</label>
          <div class="control">
            <input class="input" type="password" placeholder="********" name="password" id="password">
          </div>
        </div>
        <button class="button is-primary">Sign in</button>
        {{ end }}
    </form>
    </div>
  </section>

  <footer class="footer has-text-grey has-background-light is-size-7">
    <div class="content has-text-centered">
    	{{ if eq .Footer "-" }}
    	{{ else if eq .Footer ""}}
    	<p>Secured with <a href="https://github.com/oauth2-proxy/oauth2-proxy#oauth2_proxy" class="has-text-grey">OAuth2 Proxy</a> version {{.Version}}</p>
    	{{ else }}
    	<p>{{.Footer}}</p>
    	{{ end }}
    </div>
	</footer>

  </body>
</html>
{{end}}`
)

// LoadTemplates adds the Sign In and Error templates from the custom template
// directory, or uses the defaults if they do not exist or the custom directory
// is not provided.
func LoadTemplates(customDir string) (*template.Template, error) {
	t := template.New("").Funcs(template.FuncMap{
		"ToUpper": strings.ToUpper,
		"ToLower": strings.ToLower,
	})
	var err error
	t, err = addTemplate(t, customDir, signInTemplateName, defaultSignInTemplate)
	if err != nil {
		return nil, fmt.Errorf("could not add Sign In template: %v", err)
	}
	t, err = addTemplate(t, customDir, errorTemplateName, defaultErrorTemplate)
	if err != nil {
		return nil, fmt.Errorf("could not add Error template: %v", err)
	}

	return t, nil
}

// addTemplate will add the template from the custom directory if provided,
// else it will add the default template.
func addTemplate(t *template.Template, customDir, fileName, defaultTemplate string) (*template.Template, error) {
	filePath := filepath.Join(customDir, fileName)
	if customDir != "" && isFile(filePath) {
		t, err := t.ParseFiles(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %v", filePath, err)
		}
		return t, nil
	}
	t, err := t.Parse(defaultTemplate)
	if err != nil {
		// This should not happen.
		// Default templates should be tested and so should never fail to parse.
		logger.Panic("Could not parse defaultTemplate: ", err)
	}
	return t, nil
}

// isFile checks if the file exists and checks whether it is a regular file.
// If either of these fail then it cannot be used as a template file.
func isFile(fileName string) bool {
	info, err := os.Stat(fileName)
	if err != nil {
		logger.Errorf("Could not load file %s: %v, will use default template", fileName, err)
		return false
	}
	return info.Mode().IsRegular()
}
