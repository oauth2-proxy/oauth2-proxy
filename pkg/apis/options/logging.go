package options

import (
	"github.com/spf13/pflag"
)

// Logging contains all options required for configuring the logging
type Logging struct {
	Level           string         `flag:"logging-level" cfg:"logging_level"`
	Format          string         `flag:"logging-format" cfg:"logging_format"`
	AuthEnabled     bool           `flag:"auth-logging" cfg:"auth_logging"`
	RequestEnabled  bool           `flag:"request-logging" cfg:"request_logging"`
	ErrToInfo       bool           `flag:"errors-to-info-log" cfg:"errors_to_info_log"`
	ExcludePaths    []string       `flag:"exclude-logging-path" cfg:"exclude_logging_paths"`
	LocalTime       bool           `flag:"logging-local-time" cfg:"logging_local_time"`
	SilencePing     bool           `flag:"silence-ping-logging" cfg:"silence_ping_logging"`
	RequestIDHeader string         `flag:"request-id-header" cfg:"request_id_header"`
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

	flagSet.String("logging-level", "info", "Log level: debug, info, warn, error")
	flagSet.String("logging-format", "json", "Log format: json, text")
	flagSet.Bool("auth-logging", true, "Log authentication attempts")
	flagSet.Bool("request-logging", true, "Log HTTP requests")
	flagSet.Bool("errors-to-info-log", false, "Log errors to the standard logging channel instead of stderr")

	flagSet.StringSlice("exclude-logging-path", []string{}, "Exclude logging requests to paths (eg: '/path1,/path2,/path3')")
	flagSet.Bool("logging-local-time", true, "If the time in log files and backup filenames are local or UTC time")
	flagSet.Bool("silence-ping-logging", false, "Disable logging of requests to ping & ready endpoints")
	flagSet.String("request-id-header", "X-Request-Id", "Request header to use as the request ID")

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
		Level:           "info",
		Format:          "json",
		ExcludePaths:    nil,
		LocalTime:       true,
		SilencePing:     false,
		RequestIDHeader: "X-Request-Id",
		AuthEnabled:     true,
		RequestEnabled:  true,
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
