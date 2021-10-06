package requests

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"k8s.io/klog/v2"
)

var (
	debugLogger = func() klog.Verbose { return klog.V(logger.RequestDebug) }
	traceLogger = func() klog.Verbose { return klog.V(logger.RequestTrace) }
)
