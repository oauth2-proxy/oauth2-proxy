package options

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// Logging contains all options required for configuring the logging
type Logging struct {
	AuthEnabled     bool           `yaml:"authEnabled"`
	AuthFormat      string         `yaml:"authFormat,omitempty"`
	RequestEnabled  bool           `yaml:"requestEnabled"`
	RequestFormat   string         `yaml:"requestFormat,omitempty"`
	StandardEnabled bool           `yaml:"standardEnabled"`
	StandardFormat  string         `yaml:"standardFormat,omitempty"`
	ErrToInfo       bool           `yaml:"errToInfo,omitempty"`
	ExcludePaths    []string       `yaml:"excludePaths,omitempty"`
	LocalTime       bool           `yaml:"localTime"`
	SilencePing     bool           `yaml:"silencePing,omitempty"`
	RequestIDHeader string         `yaml:"requestIdHeader,omitempty"`
	File            LogFileOptions `yaml:"fileOptions,omitempty"`
}

// LogFileOptions contains options for configuring logging to a file
type LogFileOptions struct {
	Filename   string `yaml:"filename,omitempty"`
	MaxSize    int    `yaml:"maxSize,omitempty"`
	MaxAge     int    `yaml:"maxAge,omitempty"`
	MaxBackups int    `yaml:"maxBackups,omitempty"`
	Compress   bool   `yaml:"compress,omitempty"`
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
