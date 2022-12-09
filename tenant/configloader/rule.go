package configloader

import (
	"fmt"
	"net/http"
	"regexp"
)

type RuleSource string

const (
	SourceHost        RuleSource = "host"
	SourcePath        RuleSource = "path"
	SourceQueryParams RuleSource = "query"
	SourceHeader      RuleSource = "header"
)

type RuleConfig struct {
	Source       RuleSource // which part of the HTTP request contains the tenant id
	Expr         string     // the regex expression to match and extract tenant id from the source
	CaptureGroup int        // capture group or sub-match that is actually the tenant id
	QueryParam   string     // query parameter in case source is 'query'
	Header       string     // header key in case source is 'header'
}

type rule struct {
	conf   *RuleConfig
	regexp *regexp.Regexp
}

func newRule(conf RuleConfig) (*rule, error) {
	if conf.CaptureGroup < 0 {
		return nil, fmt.Errorf("capture group cannot be -ve")
	}
	r := &rule{
		conf: &conf,
	}
	regexp, err := regexp.Compile(conf.Expr)
	if err != nil {
		return nil, fmt.Errorf("unable to compile regexp '%s': %w", conf.Expr, err)
	}
	r.regexp = regexp
	return r, nil
}

func (r *rule) execute(req *http.Request) string {
	sourceStr := ""
	// get the source string based on rule.source
	switch r.conf.Source {
	case SourceHost:
		sourceStr = req.Host
	case SourcePath:
		sourceStr = req.URL.Path
	case SourceQueryParams:
		sourceStr = req.URL.Query().Get(r.conf.QueryParam)
	case SourceHeader:
		sourceStr = req.Header.Get(r.conf.Header)
	}

	// get the capture groups
	cgs := r.regexp.FindStringSubmatch(sourceStr)
	if r.conf.CaptureGroup < len(cgs) {
		return cgs[r.conf.CaptureGroup]
	}
	return ""
}
