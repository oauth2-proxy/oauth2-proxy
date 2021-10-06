package providers

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"k8s.io/klog/v2"
)

var (
	infoLogger  = func() klog.Verbose { return klog.V(logger.ProviderInfo) }
	debugLogger = func() klog.Verbose { return klog.V(logger.ProviderDebug) }
	traceLogger = func() klog.Verbose { return klog.V(logger.ProviderTrace) }
)
