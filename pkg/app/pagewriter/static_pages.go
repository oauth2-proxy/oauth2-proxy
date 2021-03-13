package pagewriter

import (
	// Import embed to allow importing default page templates
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

const (
	robotsTxtName = "robots.txt"
)

//go:embed robots.txt
var defaultRobotsTxt []byte

// staticPageWriter is used to write static pages.
type staticPageWriter struct {
	pages           map[string][]byte
	errorPageWriter *errorPageWriter
}

// WriteRobotsTxt writes the robots.txt content to the response writer.
func (s *staticPageWriter) WriteRobotsTxt(rw http.ResponseWriter, req *http.Request) {
	s.writePage(rw, req, robotsTxtName)
}

// writePage writes the content of the page to the response writer.
func (s *staticPageWriter) writePage(rw http.ResponseWriter, req *http.Request, pageName string) {
	content, ok := s.pages[pageName]
	if !ok {
		// If the page isn't regiested, something went wrong and there is a bug.
		// Tests should make sure this code path is never hit.
		panic(fmt.Sprintf("Static page %q not found", pageName))
	}
	_, err := rw.Write(content)
	if err != nil {
		logger.Printf("Error writing %q: %v", pageName, err)
		scope := middlewareapi.GetRequestScope(req)
		s.errorPageWriter.WriteErrorPage(rw, ErrorPageOpts{
			Status:    http.StatusInternalServerError,
			RequestID: scope.RequestID,
			AppError:  err.Error(),
		})
		return
	}
}

func newStaticPageWriter(customDir string, errorWriter *errorPageWriter) (*staticPageWriter, error) {
	pages, err := loadStaticPages(customDir)
	if err != nil {
		return nil, fmt.Errorf("could not load static pages: %v", err)
	}

	return &staticPageWriter{
		pages:           pages,
		errorPageWriter: errorWriter,
	}, nil
}

// loadStaticPages loads static page content from the custom directory provided.
// If any file is not provided in the custom directory, the default will be used
// instead.
// Statis files include:
// - robots.txt
func loadStaticPages(customDir string) (map[string][]byte, error) {
	pages := make(map[string][]byte)

	if err := addStaticPage(pages, customDir, robotsTxtName, defaultRobotsTxt); err != nil {
		return nil, fmt.Errorf("could not add robots.txt: %v", err)
	}

	return pages, nil
}

// addStaticPage tries to load the named file from the custom directory.
// If no custom directory is provided, the default content is used instead.
func addStaticPage(pages map[string][]byte, customDir, fileName string, defaultContent []byte) error {
	filePath := filepath.Join(customDir, fileName)
	if customDir != "" && isFile(filePath) {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("could not read file: %v", err)
		}

		pages[fileName] = content
		return nil
	}

	// No custom content defined, use the default.
	pages[fileName] = defaultContent
	return nil
}
