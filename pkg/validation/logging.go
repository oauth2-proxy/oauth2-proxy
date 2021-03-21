package validation

import (
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"gopkg.in/natefinch/lumberjack.v2"
)

// configureLogger is responsible for configuring the logger based on the options given
func configureLogger(o options.Logging, msgs []string) []string {
	// Setup the log file
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

		logger.Printf("Redirecting logging to file: %s", o.File.Filename)

		logWriter := &lumberjack.Logger{
			Filename:   o.File.Filename,
			MaxSize:    o.File.MaxSize, // megabytes
			MaxAge:     o.File.MaxAge,  // days
			MaxBackups: o.File.MaxBackups,
			LocalTime:  o.LocalTime,
			Compress:   o.File.Compress,
		}

		logger.SetOutput(logWriter)
	}

	// Supply a sanity warning to the logger if all logging is disabled
	if !o.StandardEnabled && !o.AuthEnabled && !o.RequestEnabled {
		logger.Error("Warning: Logging disabled. No further logs will be shown.")
	}

	// Pass configuration values to the standard logger
	logger.SetStandardEnabled(o.StandardEnabled)
	logger.SetErrToInfo(o.ErrToInfo)
	logger.SetAuthEnabled(o.AuthEnabled)
	logger.SetReqEnabled(o.RequestEnabled)
	logger.SetStandardTemplate(o.StandardFormat)
	logger.SetAuthTemplate(o.AuthFormat)
	logger.SetReqTemplate(o.RequestFormat)

	logger.SetExcludePaths(o.ExcludePaths)

	if !o.LocalTime {
		logger.SetFlags(logger.Flags() | logger.LUTC)
	}

	return msgs
}
