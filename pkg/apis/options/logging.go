package options

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// Logging contains all options required for configuring the logging
type Logging struct {
	AuthEnabled     bool           `json:"authEnabled"`
	AuthFormat      string         `json:"authFormat,omitempty"`
	RequestEnabled  bool           `json:"requestEnabled"`
	RequestFormat   string         `json:"requestFormat,omitempty"`
	StandardEnabled bool           `json:"standardEnabled"`
	StandardFormat  string         `json:"standardFormat,omitempty"`
	ErrToInfo       bool           `json:"errToInfo"`
	ExcludePaths    []string       `json:"excludePaths,omitempty"`
	LocalTime       bool           `json:"localTime"`
	SilencePing     bool           `json:"silencePing"`
	RequestIDHeader string         `json:"requestIdHeader,omitempty"`
	File            LogFileOptions `json:"fileOptions,omitempty"`
}

// LogFileOptions contains options for configuring logging to a file
type LogFileOptions struct {
	Filename   string `json:"filename,omitempty"`
	MaxSize    int    `json:"maxSize,omitempty"`
	MaxAge     int    `json:"maxAge,omitempty"`
	MaxBackups int    `json:"maxBackups,omitempty"`
	Compress   bool   `json:"compress,omitempty"`
}

// loggingDefaults creates a Logging structure, populating each field with its default value
func loggingDefaults() Logging {
	return Logging{
		ExcludePaths:    nil,
		LocalTime:       true,
		SilencePing:     false,
		RequestIDHeader: "X-Request-Id",
		AuthEnabled:     true,
		AuthFormat:      logger.DefaultAuthLoggingFormat,
		RequestEnabled:  true,
		RequestFormat:   logger.DefaultRequestLoggingFormat,
		StandardEnabled: true,
		StandardFormat:  logger.DefaultStandardLoggingFormat,
		ErrToInfo:       false,
		File: LogFileOptions{
			Filename:   "",
			MaxSize:    100,
			MaxAge:     7,
			MaxBackups: 0,
			Compress:   false,
		},
	}
}
