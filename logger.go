package main

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"k8s.io/klog/v2"
)

var (
	infoLogger  = func() klog.Verbose { return klog.V(logger.CoreInfo) }
	debugLogger = func() klog.Verbose { return klog.V(logger.CoreDebug) }
	traceLogger = func() klog.Verbose { return klog.V(logger.CoreTrace) }
)
