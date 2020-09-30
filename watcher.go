// +build go1.3,!plan9,!solaris

package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// WaitForReplacement waits for a file to exist on disk and then starts a watch
// for the file
func WaitForReplacement(filename string, op fsnotify.Op,
	watcher *fsnotify.Watcher) {
	const sleepInterval = 50 * time.Millisecond

	// Avoid a race when fsnofity.Remove is preceded by fsnotify.Chmod.
	if op&fsnotify.Chmod != 0 {
		time.Sleep(sleepInterval)
	}
	for {
		if _, err := os.Stat(filename); err == nil {
			if err := watcher.Add(filename); err == nil {
				logger.Printf("watching resumed for %s", filename)
				return
			}
		}
		time.Sleep(sleepInterval)
	}
}

// WatchForUpdates performs an action every time a file on disk is updated
func WatchForUpdates(filename string, done <-chan bool, action func()) {
	filename = filepath.Clean(filename)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Fatal("failed to create watcher for ", filename, ": ", err)
	}
	go func() {
		defer func(w *fsnotify.Watcher) {
			cerr := w.Close()
			if cerr != nil {
				logger.Fatalf("error closing watcher: %v", err)
			}
		}(watcher)
		for {
			select {
			case <-done:
				logger.Printf("Shutting down watcher for: %s", filename)
				return
			case event := <-watcher.Events:
				// On Arch Linux, it appears Chmod events precede Remove events,
				// which causes a race between action() and the coming Remove event.
				// If the Remove wins, the action() (which calls
				// UserMap.LoadAuthenticatedEmailsFile()) crashes when the file
				// can't be opened.
				if event.Op&(fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) != 0 {
					logger.Printf("watching interrupted on event: %s", event)
					err = watcher.Remove(filename)
					if err != nil {
						logger.Printf("error removing watcher on %s: %v", filename, err)
					}
					WaitForReplacement(filename, event.Op, watcher)
				}
				logger.Printf("reloading after event: %s", event)
				action()
			case err = <-watcher.Errors:
				logger.Errorf("error watching %s: %s", filename, err)
			}
		}
	}()
	if err = watcher.Add(filename); err != nil {
		logger.Fatal("failed to add ", filename, " to watcher: ", err)
	}
	logger.Printf("watching %s for updates", filename)
}
