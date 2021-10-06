package requests

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

var (
	debugLogger = logger.Verbose(logger.RequestDebug)
	traceLogger = logger.Verbose(logger.RequestTrace)
)
