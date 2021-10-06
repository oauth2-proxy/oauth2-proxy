package main

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

var (
	infoLogger  = logger.Verbose(logger.CoreInfo)
	debugLogger = logger.Verbose(logger.CoreDebug)
	traceLogger = logger.Verbose(logger.CoreTrace)
)
