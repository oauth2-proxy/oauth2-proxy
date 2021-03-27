package clock

import (
	"errors"
	"sync"
	"time"

	clockapi "github.com/benbjohnson/clock"
)

var (
	globalClock = clockapi.New()
	mu          sync.Mutex
)

// Set the global clock to a clockapi.Mock with the given time.Time
func Set(t time.Time) {
	mu.Lock()
	defer mu.Unlock()
	mock, ok := globalClock.(*clockapi.Mock)
	if !ok {
		mock = clockapi.NewMock()
	}
	mock.Set(t)
	globalClock = mock
}

// Add moves the mocked global clock forward the given duration. It will error
// if the global clock is not mocked.
func Add(d time.Duration) error {
	mu.Lock()
	defer mu.Unlock()
	mock, ok := globalClock.(*clockapi.Mock)
	if !ok {
		return errors.New("time not mocked")
	}
	mock.Add(d)
	return nil
}

// Reset sets the global clock to a pure time implementation
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	globalClock = clockapi.New()
}

// Clock is a non-package level wrapper around time that supports stubbing.
// It will use its localized stubs (allowing for parallelized unit tests
// where package level stubbing would cause issues). It falls back to any
// package level time stubs for non-parallel, cross-package integration
// testing scenarios.
//
// If nothing is stubbed, it defaults to default time behavior in the time
// package.
type Clock interface {
	After(time.Duration) <-chan time.Time
	AfterFunc(time.Duration, func()) *clockapi.Timer
	Now() time.Time
	Since(time.Time) time.Duration
	Sleep(time.Duration)
	Tick(time.Duration) <-chan time.Time
	Ticker(time.Duration) *clockapi.Ticker
	Timer(time.Duration) *clockapi.Timer

	Set(time.Time)
	Add(time.Duration) error
	Reset()
}

type clock struct {
	mock *clockapi.Mock
	sync.Mutex
}

// New returns a Clock that defaults to generic `time` functionality.
// It can be stubbed locally or fall back to package-level clock mocks.
func New() Clock {
	return &clock{}
}

// Set sets the Clock to a clock.Mock at the given time.Time
func (c *clock) Set(t time.Time) {
	c.Lock()
	defer c.Unlock()
	if c.mock == nil {
		c.mock = clockapi.NewMock()
	}
	c.mock.Set(t)
}

// Add moves clock forward time.Duration if it is mocked. It will error
// if the clock is not mocked.
func (c *clock) Add(d time.Duration) error {
	c.Lock()
	defer c.Unlock()
	if c.mock == nil {
		return errors.New("clock not mocked")
	}
	c.mock.Add(d)
	return nil
}

// Reset removes local clock.Mock
func (c *clock) Reset() {
	c.Lock()
	defer c.Unlock()
	c.mock = nil
}

func (c *clock) After(d time.Duration) <-chan time.Time {
	if c.mock == nil {
		return globalClock.After(d)
	}
	return c.mock.After(d)
}

func (c *clock) AfterFunc(d time.Duration, f func()) *clockapi.Timer {
	if c.mock == nil {
		return globalClock.AfterFunc(d, f)
	}
	return c.mock.AfterFunc(d, f)
}

func (c *clock) Now() time.Time {
	if c.mock == nil {
		return globalClock.Now()
	}
	return c.mock.Now()
}

func (c *clock) Since(t time.Time) time.Duration {
	if c.mock == nil {
		return globalClock.Since(t)
	}
	return c.mock.Since(t)
}

func (c *clock) Sleep(d time.Duration) {
	if c.mock == nil {
		globalClock.Sleep(d)
		return
	}
	c.mock.Sleep(d)
}

func (c *clock) Tick(d time.Duration) <-chan time.Time {
	if c.mock == nil {
		return globalClock.Tick(d)
	}
	return c.mock.Tick(d)
}

func (c *clock) Ticker(d time.Duration) *clockapi.Ticker {
	if c.mock == nil {
		return globalClock.Ticker(d)
	}
	return c.mock.Ticker(d)
}

func (c *clock) Timer(d time.Duration) *clockapi.Timer {
	if c.mock == nil {
		return globalClock.Timer(d)
	}
	return c.mock.Timer(d)
}
