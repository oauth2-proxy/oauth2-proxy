package main

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestLevelFlagSetLevel(t *testing.T) {
	lf := NewLevelFlagAt(zap.InfoLevel)
	t.Logf("Initial lf = %d", lf)
	expected := zap.WarnLevel
	t.Logf("Setting level : %d", expected)
	lf.Set("warn")

	t.Logf("After Set() : lf = %d, Get() = %d", lf, lf.Get())
	if zapcore.Level(lf.Get().(LevelFlag)) != expected {
		t.Error("SetLevel failed")
	}
}

var leveltests = []struct {
	in  zapcore.Level
	out string
}{
	{zap.DebugLevel, "debug"},
	{zap.InfoLevel, "info"},
	{zap.WarnLevel, "warn"},
	{zap.ErrorLevel, "error"},
	{zap.FatalLevel, "fatal"},
	{zap.PanicLevel, "panic"},
}

func TestLevelFlagString(t *testing.T) {
	for _, tt := range leveltests {
		t.Run(tt.in.String(), func(t *testing.T) {
			lf := NewLevelFlagAt(tt.in)
			if lf.String() != tt.out {
				t.Errorf("got %q, want %q:", lf.String(), tt.out)
			}
		})
	}
}

func TestLevelFlagSet(t *testing.T) {
	for _, tt := range leveltests {
		t.Run(tt.in.String(), func(t *testing.T) {
			lf := NewLevelFlagAt(zap.InfoLevel)
			lf.Set(tt.out)
			val := lf.Get().(LevelFlag)
			if zapcore.Level(val) != tt.in {
				t.Errorf("got %q, want %q:", val, tt.in)
			}
		})
	}
}
