package providers

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

var (
	infoLogger  = logger.Verbose(logger.ProviderInfo)
	debugLogger = logger.Verbose(logger.ProviderDebug)
	traceLogger = logger.Verbose(logger.ProviderTrace)
)
