package main

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"k8s.io/klog/v2"
)

var (
	infoLogger  = klog.V(logger.CoreInfo)
	debugLogger = klog.V(logger.CoreDebug)
	traceLogger = klog.V(logger.CoreTrace)
)
