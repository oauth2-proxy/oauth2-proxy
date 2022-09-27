package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// WatchFileForUpdates performs an action every time a file on disk is updated
func WatchFileForUpdates(filename string, done <-chan bool, action func()) error {
	filename = filepath.Clean(filename)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher for '%s': %s", filename, err)
	}

	go func() {
		defer watcher.Close()

		for {
			select {
			case <-done:
				logger.Printf("shutting down watcher for: %s", filename)
				return
			case event := <-watcher.Events:
				filterEvent(watcher, event, filename, action)
			case err = <-watcher.Errors:
				logger.Errorf("error watching '%s': %s", filename, err)
			}
		}
	}()
	if err := watcher.Add(filename); err != nil {
		return fmt.Errorf("failed to add '%s' to watcher: %v", filename, err)
	}
	logger.Printf("watching '%s' for updates", filename)

	return nil
}

// Filter file operations based on the events sent by the watcher.
// Execute the action() function when the following conditions are met:
//  - the real path of the file was changed (Kubernetes ConfigMap/Secret)
//  - the file is modified or created
func filterEvent(watcher *fsnotify.Watcher, event fsnotify.Event, filename string, action func()) {
	switch filepath.Clean(event.Name) == filename {
	// In Kubernetes the file path is a symlink, so we should take action
	// when the ConfigMap/Secret is replaced.
	case event.Op&fsnotify.Remove != 0:
		logger.Printf("watching interrupted on event: %s", event)
		WaitForReplacement(filename, event.Op, watcher)
		action()
	case event.Op&(fsnotify.Create|fsnotify.Write) != 0:
		logger.Printf("reloading after event: %s", event)
		action()
	}
}

// WaitForReplacement waits for a file to exist on disk and then starts a watch
// for the file
func WaitForReplacement(filename string, op fsnotify.Op, watcher *fsnotify.Watcher) {
	const sleepInterval = 50 * time.Millisecond

	// Avoid a race when fsnofity.Remove is preceded by fsnotify.Chmod.
	if op&fsnotify.Chmod != 0 {
		time.Sleep(sleepInterval)
	}
	for {
		if _, err := os.Stat(filename); err == nil {
			if err := watcher.Add(filename); err == nil {
				logger.Printf("watching resumed for '%s'", filename)
				return
			}
		}
		time.Sleep(sleepInterval)
	}
}
