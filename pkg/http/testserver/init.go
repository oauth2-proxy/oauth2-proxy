package main

import (
	"os"
	"strconv"
)

func init() {
	if os.Getenv("FIX_LISTEN_PID") == "1" {
		os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		os.Unsetenv("FIX_LISTEN_PID")
	}
}
