package validation

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"gopkg.in/natefinch/lumberjack.v2"
)

// parseLogLevel converts a string log level to slog.Level.
func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level %q: must be one of debug, info, warn, error", s)
	}
}

// configureLogger is responsible for configuring the logger based on the options given
func configureLogger(o options.Logging, msgs []string) []string {
	// Parse and validate log level
	level, err := parseLogLevel(o.Level)
	if err != nil {
		msgs = append(msgs, err.Error())
		return msgs
	}

	// Validate log format
	format := strings.ToLower(o.Format)
	if format != "json" && format != "text" {
		msgs = append(msgs, fmt.Sprintf("invalid log format %q: must be one of json, text", o.Format))
		return msgs
	}

	// Determine output writers
	if len(o.File.Filename) > 0 {
		// Validate that the file/dir can be written
		file, err := os.OpenFile(o.File.Filename, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			if os.IsPermission(err) {
				return append(msgs, "unable to write to log file: "+o.File.Filename)
			}
		}
		err = file.Close()
		if err != nil {
			return append(msgs, "error closing the log file: "+o.File.Filename)
		}
	}

	// Setup writers
	var stdWriter, errWriter *os.File
	stdWriter = os.Stdout
	errWriter = os.Stderr

	if len(o.File.Filename) > 0 {
		logWriter := &lumberjack.Logger{
			Filename:   o.File.Filename,
			MaxSize:    o.File.MaxSize, // megabytes
			MaxAge:     o.File.MaxAge,  // days
			MaxBackups: o.File.MaxBackups,
			LocalTime:  o.LocalTime,
			Compress:   o.File.Compress,
		}

		// Setup with lumberjack writer
		errW := errWriter
		if o.ErrToInfo {
			logger.Setup(level, format, logWriter, logWriter)
		} else {
			logger.Setup(level, format, logWriter, errW)
		}

		logger.Info("logging redirected to file", "filename", o.File.Filename)
	} else {
		// Setup with stdout/stderr
		if o.ErrToInfo {
			logger.Setup(level, format, stdWriter, stdWriter)
		} else {
			logger.Setup(level, format, stdWriter, errWriter)
		}
	}

	// Supply a sanity warning to the logger if all logging is disabled
	if !o.AuthEnabled && !o.RequestEnabled {
		logger.Warn("all categorical logging disabled: auth and request logging are both off")
	}

	// Configure categorical logging
	logger.SetAuthEnabled(o.AuthEnabled)
	logger.SetReqEnabled(o.RequestEnabled)

	// Configure exclude paths
	excludePaths := o.ExcludePaths
	if o.SilencePing {
		excludePaths = append(excludePaths, "/ping", "/ready")
	}
	logger.SetExcludePaths(excludePaths)

	return msgs
}
