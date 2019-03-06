package main

import (
	"go.uber.org/zap/zapcore"
)

// LevelFlag is a Zap log level
type LevelFlag zapcore.Level

// NewLevelFlagAt creates a LevelFlag at the given level
func NewLevelFlagAt(l zapcore.Level) LevelFlag {
	return LevelFlag(l)
}

// Set sets a new value to LevelFlag
func (lf *LevelFlag) Set(s string) error {
	buf := []byte(s)
	var lvl zapcore.Level
	err := lvl.UnmarshalText(buf)
	*lf = LevelFlag(lvl)
	return err
}

// Level returns the level as AtomicLevel
func (lf *LevelFlag) Level() zapcore.Level {
	return zapcore.Level(*lf)
}

// Get returns the LevelFlag value
func (lf *LevelFlag) Get() interface{} {
	return LevelFlag(*lf)
}

// String() returns the string representation
func (lf *LevelFlag) String() string {
	lvl := zapcore.Level(*lf)
	return lvl.String()
}
