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
	pageGetter      *pageGetter
	errorPageWriter *errorPageWriter
}

// WriteRobotsTxt writes the robots.txt content to the response writer.
func (s *staticPageWriter) WriteRobotsTxt(rw http.ResponseWriter, req *http.Request) {
	s.writePage(rw, req, robotsTxtName)
}

// writePage writes the content of the page to the response writer.
func (s *staticPageWriter) writePage(rw http.ResponseWriter, req *http.Request, pageName string) {
	_, err := rw.Write(s.pageGetter.getPage(pageName))
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
	pageGetter, err := loadStaticPages(customDir)
	if err != nil {
		return nil, fmt.Errorf("could not load static pages: %v", err)
	}

	return &staticPageWriter{
		pageGetter:      pageGetter,
		errorPageWriter: errorWriter,
	}, nil
}

// loadStaticPages loads static page content from the custom directory provided.
// If any file is not provided in the custom directory, the default will be used
// instead.
// Statis files include:
// - robots.txt
func loadStaticPages(customDir string) (*pageGetter, error) {
	pages := newPageGetter(customDir)

	if err := pages.addPage(robotsTxtName, defaultRobotsTxt); err != nil {
		return nil, fmt.Errorf("could not add robots.txt: %v", err)
	}

	return pages, nil
}

// pageGetter is used to load and read page content for static pages.
type pageGetter struct {
	pages map[string][]byte
	dir   string
}

// newPageGetter creates a new page getter for the custom directory.
func newPageGetter(customDir string) *pageGetter {
	return &pageGetter{
		pages: make(map[string][]byte),
		dir:   customDir,
	}
}

// addPage loads a new page into the pageGetter.
// If the given file name does not exist in the custom directory, the default
// content will be used instead.
func (p *pageGetter) addPage(fileName string, defaultContent []byte) error {
	filePath := filepath.Join(p.dir, fileName)
	if p.dir != "" && isFile(filePath) {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("could not read file: %v", err)
		}

		p.pages[fileName] = content
		return nil
	}

	// No custom content defined, use the default.
	p.pages[fileName] = defaultContent
	return nil
}

// getPage returns the page content for a given page.
func (p *pageGetter) getPage(name string) []byte {
	content, ok := p.pages[name]
	if !ok {
		// If the page isn't registered, something went wrong and there is a bug.
		// Tests should make sure this code path is never hit.
		panic(fmt.Sprintf("Static page %q not found", name))
	}
	return content
}
