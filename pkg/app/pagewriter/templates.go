package pagewriter

import (
	// Import embed to allow importing default page templates
	_ "embed"

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
)

//go:embed error.html
var defaultErrorTemplate string

//go:embed sign_in.html
var defaultSignInTemplate string

// loadTemplates adds the Sign In and Error templates from the custom template
// directory, or uses the defaults if they do not exist or the custom directory
// is not provided.
func loadTemplates(customDir string) (*template.Template, error) {
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
