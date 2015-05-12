// +build go1.1
// +build plan9,solaris

package main

import (
	"log"
)

func WatchForUpdates(filename string, action func()) bool {
	log.Printf("file watching not implemented on this platform")
	return false
}
