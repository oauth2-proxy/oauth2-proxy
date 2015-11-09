// +build go1.3,!plan9,!solaris

package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/fsnotify.v1"
)

func WaitForReplacement(filename string, op fsnotify.Op,
	watcher *fsnotify.Watcher) {
	const sleep_interval = 50 * time.Millisecond

	// Avoid a race when fsnofity.Remove is preceded by fsnotify.Chmod.
	if op&fsnotify.Chmod != 0 {
		time.Sleep(sleep_interval)
	}
	for {
		if _, err := os.Stat(filename); err == nil {
			if err := watcher.Add(filename); err == nil {
				log.Printf("watching resumed for %s", filename)
				return
			}
		}
		time.Sleep(sleep_interval)
	}
}

func WatchForUpdates(filename string, done <-chan bool, action func()) {
	filename = filepath.Clean(filename)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("failed to create watcher for ", filename, ": ", err)
	}
	go func() {
		defer watcher.Close()
		for {
			select {
			case _ = <-done:
				log.Printf("Shutting down watcher for: %s", filename)
				break
			case event := <-watcher.Events:
				// On Arch Linux, it appears Chmod events precede Remove events,
				// which causes a race between action() and the coming Remove event.
				// If the Remove wins, the action() (which calls
				// UserMap.LoadAuthenticatedEmailsFile()) crashes when the file
				// can't be opened.
				if event.Op&(fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) != 0 {
					log.Printf("watching interrupted on event: %s", event)
					watcher.Remove(filename)
					WaitForReplacement(filename, event.Op, watcher)
				}
				log.Printf("reloading after event: %s", event)
				action()
			case err := <-watcher.Errors:
				log.Printf("error watching %s: %s", filename, err)
			}
		}
	}()
	if err = watcher.Add(filename); err != nil {
		log.Fatal("failed to add ", filename, " to watcher: ", err)
	}
	log.Printf("watching %s for updates", filename)
}
