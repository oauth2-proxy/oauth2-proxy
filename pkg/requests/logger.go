package requests

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"k8s.io/klog/v2"
)

var (
	debugLogger = klog.V(logger.RequestDebug)
	traceLogger = klog.V(logger.RequestTrace)
)
