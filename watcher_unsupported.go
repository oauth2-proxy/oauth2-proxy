// +build !go1.3 plan9 solaris

package main

import "k8s.io/klog/v2"

func WatchForUpdates(filename string, done <-chan bool, action func()) {
	klog.Errorf("file watching not implemented on this platform")
	go func() { <-done }()
}
