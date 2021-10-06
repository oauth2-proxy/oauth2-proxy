package logger

import (
	"fmt"

	"k8s.io/klog/v2"
)

type Verbose int32

func (v Verbose) Enabled() bool {
	return klog.V(klog.Level(v)).Enabled()
}

func (v Verbose) Infof(msg string, args ...interface{}) {
	klog.V(klog.Level(v)).Infof(msg, args...)
}

func (v Verbose) Errorf(err error, msg string, args ...interface{}) {
	klog.V(klog.Level(v)).ErrorS(err, fmt.Sprintf(msg, args...))
}
