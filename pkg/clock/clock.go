package clock

import (
	"errors"
	"sync"
	"time"

	clockapi "github.com/jonboulle/clockwork"
)

var (
	globalClock clockapi.Clock = clockapi.NewRealClock()
	mu          sync.Mutex
)

// Set the globalClock to a new mock clock at the specified time.Time.
func Set(t time.Time) {
	mu.Lock()
	defer mu.Unlock()

	globalClock = clockapi.NewFakeClockAt(t)
}

// Add moves the mocked global clock forward the given time.Duration.
// It will error if the global clock is not mocked.
func Add(d time.Duration) error {
	mu.Lock()
	defer mu.Unlock()

	mock, ok := globalClock.(clockapi.FakeClock)
	if !ok {
		return errors.New("time not mocked")
	}
	mock.Advance(d)
	return nil
}

// Reset sets the global clock to a pure time implementation.
// Returns any existing Mock if set in case lingering time operations are attached to it.
func Reset() clockapi.FakeClock {
	mu.Lock()
	defer mu.Unlock()

	existing := globalClock
	globalClock = clockapi.NewRealClock()

	mock, ok := existing.(clockapi.FakeClock)
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
	mock clockapi.FakeClock
}

// Set sets the Clock to a new mock clock at the specified time.Time.
func (c *Clock) Set(t time.Time) {
	c.mock = clockapi.NewFakeClockAt(t)
}

// Add moves clock forward time.Duration if it is mocked.
// It will error if the clock is not mocked.
func (c *Clock) Add(d time.Duration) error {
	if c.mock == nil {
		return errors.New("clock not mocked")
	}
	c.mock.Advance(d)
	return nil
}

// Reset removes local Clock.mock and returns any existing mock if it's set, in case lingering time operations are attached to it.
func (c *Clock) Reset() clockapi.FakeClock {
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

func (c *Clock) AfterFunc(d time.Duration, f func()) clockapi.Timer {
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
		return globalClock.NewTicker(d).Chan()
	}
	return m.NewTicker(d).Chan()
}

func (c *Clock) Ticker(d time.Duration) clockapi.Ticker {
	m := c.mock
	if m == nil {
		return globalClock.NewTicker(d)
	}
	return m.NewTicker(d)
}

func (c *Clock) Timer(d time.Duration) clockapi.Timer {
	m := c.mock
	if m == nil {
		return globalClock.NewTimer(d)
	}
	return m.NewTimer(d)
}
