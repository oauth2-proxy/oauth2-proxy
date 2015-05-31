// +build !go1.3 plan9 solaris

package main

import (
	"log"
)

func WatchForUpdates(filename string, done <-chan bool, action func()) bool {
	log.Printf("file watching not implemented on this platform")
	return false
}
