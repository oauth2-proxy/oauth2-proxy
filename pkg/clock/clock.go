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

// Reset sets the global clock to a pure time implementation. Returns any
// existing Mock if set in case lingering time operations are attached to it.
func Reset() *clockapi.Mock {
	mu.Lock()
	defer mu.Unlock()
	existing := globalClock
	globalClock = clockapi.New()

	mock, ok := existing.(*clockapi.Mock)
	if !ok {
		return nil
	}
	return mock
}

// Clock is a non-package level wrapper around time that supports stubbing.
// It will use its localized stubs (allowing for parallelized unit tests
// where package level stubbing would cause issues). It falls back to any
// package level time stubs for non-parallel, cross-package integration
// testing scenarios.
//
// If nothing is stubbed, it defaults to default time behavior in the time
// package.
type Clock struct {
	mock *clockapi.Mock
}

// Set sets the Clock to a clock.Mock at the given time.Time
func (c *Clock) Set(t time.Time) {
	if c.mock == nil {
		c.mock = clockapi.NewMock()
	}
	c.mock.Set(t)
}

// Add moves clock forward time.Duration if it is mocked. It will error
// if the clock is not mocked.
func (c *Clock) Add(d time.Duration) error {
	if c.mock == nil {
		return errors.New("clock not mocked")
	}
	c.mock.Add(d)
	return nil
}

// Reset removes local clock.Mock.  Returns any existing Mock if set in case
// lingering time operations are attached to it.
func (c *Clock) Reset() *clockapi.Mock {
	existing := c.mock
	c.mock = nil
	return existing
}

func (c *Clock) After(d time.Duration) <-chan time.Time {
	m := c.mock
	if m == nil {
		return globalClock.After(d)
	}
	return m.After(d)
}

func (c *Clock) AfterFunc(d time.Duration, f func()) *clockapi.Timer {
	m := c.mock
	if m == nil {
		return globalClock.AfterFunc(d, f)
	}
	return m.AfterFunc(d, f)
}

func (c *Clock) Now() time.Time {
	m := c.mock
	if m == nil {
		return globalClock.Now()
	}
	return m.Now()
}

func (c *Clock) Since(t time.Time) time.Duration {
	m := c.mock
	if m == nil {
		return globalClock.Since(t)
	}
	return m.Since(t)
}

func (c *Clock) Sleep(d time.Duration) {
	m := c.mock
	if m == nil {
		globalClock.Sleep(d)
		return
	}
	m.Sleep(d)
}

func (c *Clock) Tick(d time.Duration) <-chan time.Time {
	m := c.mock
	if m == nil {
		return globalClock.Tick(d)
	}
	return m.Tick(d)
}

func (c *Clock) Ticker(d time.Duration) *clockapi.Ticker {
	m := c.mock
	if m == nil {
		return globalClock.Ticker(d)
	}
	return m.Ticker(d)
}

func (c *Clock) Timer(d time.Duration) *clockapi.Timer {
	m := c.mock
	if m == nil {
		return globalClock.Timer(d)
	}
	return m.Timer(d)
}
