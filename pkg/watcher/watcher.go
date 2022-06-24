package watcher

import (
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

const writeOrCreateMask = fsnotify.Write | fsnotify.Create

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
				logger.Printf("watching resumed for '%s'", filename)
				return
			}
		}
		time.Sleep(sleepInterval)
	}
}

// WatchForUpdates performs an action every time a file on disk is updated
func WatchFileForUpdates(filename string, done <-chan bool, action func()) {
	realFile, _ := filepath.EvalSymlinks(filename)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Fatalf("failed to create watcher for '%s': %s", filename, err)
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
				logger.Printf("shutting down watcher for: %s", filename)
				return
			case event, ok := <-watcher.Events:
				// 'Events' channel is closed
				if !ok {
					logger.Errorf("error: cannot start the watcher, events channel is closed")
					return
				}
				currentFile, _ := filepath.EvalSymlinks(filename)
				// we only care about the config file with the following cases:
				// 1 - if the file was modified or created
				// 2 - if the real path to the file changed (eg: k8s ConfigMap/Secret replacement)
				if (filepath.Clean(event.Name) == filename &&
					event.Op&writeOrCreateMask != 0) ||
					(currentFile != "" && currentFile != realFile) {
					logger.Printf("reloading after event: %s", event)
					realFile = currentFile
					action()
				} else if filepath.Clean(event.Name) == filename &&
					event.Op&fsnotify.Remove != 0 {
					logger.Printf("watching interrupted on event: %s", event)
					WaitForReplacement(filename, event.Op, watcher)
					if err = watcher.Add(filename); err != nil {
						logger.Fatalf("failed to add '%s' to watcher: %v", filename, err)
					}
				}
			case err = <-watcher.Errors:
				logger.Errorf("error watching '%s': %s", filename, err)
			}
		}
	}()
	if err = watcher.Add(filename); err != nil {
		logger.Fatalf("failed to add '%s' to watcher: %v", filename, err)
	}
	logger.Printf("watching '%s' for updates", filename)
}
