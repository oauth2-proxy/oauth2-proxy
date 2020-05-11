package options

// Logging contains all options required for configuring the logging
type Logging struct {
	AuthEnabled     bool           `flag:"auth-logging" cfg:"auth_logging"`
	AuthFormat      string         `flag:"auth-logging-format" cfg:"auth_logging_format"`
	RequestEnabled  bool           `flag:"request-logging" cfg:"request_logging"`
	RequestFormat   string         `flag:"request-logging-format" cfg:"request_logging_format"`
	StandardEnabled bool           `flag:"standard-logging" cfg:"standard_logging"`
	StandardFormat  string         `flag:"standard-logging-format" cfg:"standard_logging_format"`
	ExcludePaths    string         `flag:"exclude-logging-paths" cfg:"exclude_logging_paths"`
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
