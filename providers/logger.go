package providers

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"k8s.io/klog/v2"
)

var (
	infoLogger  = klog.V(logger.ProviderInfo)
	debugLogger = klog.V(logger.ProviderDebug)
	traceLogger = klog.V(logger.ProviderTrace)
)
