package options

import (
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/spf13/pflag"
)

// Logging contains all options required for configuring the logging
type Logging struct {
	AuthEnabled     bool           `flag:"auth-logging" cfg:"auth_logging"`
	AuthFormat      string         `flag:"auth-logging-format" cfg:"auth_logging_format"`
	RequestEnabled  bool           `flag:"request-logging" cfg:"request_logging"`
	RequestFormat   string         `flag:"request-logging-format" cfg:"request_logging_format"`
	StandardEnabled bool           `flag:"standard-logging" cfg:"standard_logging"`
	StandardFormat  string         `flag:"standard-logging-format" cfg:"standard_logging_format"`
	ExcludePaths    []string       `flag:"exclude-logging-path" cfg:"exclude_logging_paths"`
	LocalTime       bool           `flag:"logging-local-time" cfg:"logging_local_time"`
	SilencePing     bool           `flag:"silence-ping-logging" cfg:"silence_ping_logging"`
	File            LogFileOptions `cfg:",squash"`
}

// LogFileOptions contains options for configuring logging to a file
type LogFileOptions struct {
	Filename   string `flag:"logging-filename" cfg:"logging_filename"`
	MaxSize    int    `flag:"logging-max-size" cfg:"logging_max_size"`
	MaxAge     int    `flag:"logging-max-age" cfg:"logging_max_age"`
	MaxBackups int    `flag:"logging-max-backups" cfg:"logging_max_backups"`
	Compress   bool   `flag:"logging-compress" cfg:"logging_compress"`
}

func loggingFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("logging", pflag.ExitOnError)

	flagSet.Bool("auth-logging", true, "Log authentication attempts")
	flagSet.String("auth-logging-format", logger.DefaultAuthLoggingFormat, "Template for authentication log lines")
	flagSet.Bool("standard-logging", true, "Log standard runtime information")
	flagSet.String("standard-logging-format", logger.DefaultStandardLoggingFormat, "Template for standard log lines")
	flagSet.Bool("request-logging", true, "Log HTTP requests")
	flagSet.String("request-logging-format", logger.DefaultRequestLoggingFormat, "Template for HTTP request log lines")

	flagSet.StringSlice("exclude-logging-path", []string{}, "Exclude logging requests to paths (eg: '/path1,/path2,/path3')")
	flagSet.Bool("logging-local-time", true, "If the time in log files and backup filenames are local or UTC time")
	flagSet.Bool("silence-ping-logging", false, "Disable logging of requests to ping endpoint")

	flagSet.String("logging-filename", "", "File to log requests to, empty for stdout")
	flagSet.Int("logging-max-size", 100, "Maximum size in megabytes of the log file before rotation")
	flagSet.Int("logging-max-age", 7, "Maximum number of days to retain old log files")
	flagSet.Int("logging-max-backups", 0, "Maximum number of old log files to retain; 0 to disable")
	flagSet.Bool("logging-compress", false, "Should rotated log files be compressed using gzip")

	return flagSet
}

// loggingDefaults creates a Logging structure, populating each field with its default value
func loggingDefaults() Logging {
	return Logging{
		ExcludePaths:    nil,
		LocalTime:       true,
		SilencePing:     false,
		AuthEnabled:     true,
		AuthFormat:      logger.DefaultAuthLoggingFormat,
		RequestEnabled:  true,
		RequestFormat:   logger.DefaultRequestLoggingFormat,
		StandardEnabled: true,
		StandardFormat:  logger.DefaultStandardLoggingFormat,
		File: LogFileOptions{
			Filename:   "",
			MaxSize:    100,
			MaxAge:     7,
			MaxBackups: 0,
			Compress:   false,
		},
	}
}
