package middleware

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const zeroDuration = time.Duration(0)

// RefreshOption contains a composite cookie refresh value setting
type RefreshOption struct {
	RefreshDuration *time.Duration
	RefreshPercent  uint8
}

// NewRefreshOption creates new RefreshOption from string
func NewRefreshOption(s string) (*RefreshOption, error) {
	var r RefreshOption
	err := r.init(s)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// IsDurationBased returns true if duration
func (r *RefreshOption) IsDurationBased() bool {
	return r.RefreshDuration != nil
}

// IsDisabled returns true if refresh is disabled
func (r *RefreshOption) IsDisabled() bool {
	return r.RefreshDuration != nil && *r.RefreshDuration == zeroDuration
}

// HasExpired tells if a refresh period has expired
func (r *RefreshOption) HasExpired(now time.Time, created *time.Time, expires *time.Time) bool {
	var refreshDuration time.Duration

	if r.IsDisabled() {
		return false
	}
	if r.IsDurationBased() {
		refreshDuration = *r.RefreshDuration
	} else {
		refreshDuration = time.Duration(expires.Sub(*created).Nanoseconds() / 100.0 * int64(r.RefreshPercent))
	}
	refreshTime := created.Add(refreshDuration)

	// fmt.Printf("Refresh: created: %s, expire: %s, refresh: %s, now: %s\n", created, expires, refreshTime, now)

	return refreshTime.Before(now)
}

// Initialize RefreshOption from string
func (r *RefreshOption) init(s string) error {
	origS := s
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "%") {
		s = s[:len(s)-1]
		i, err := strconv.ParseInt(s, 10, 8)
		if err != nil {
			return fmt.Errorf("percentage \"%s\" in \"%s\" must be an integer between 1 and 100", s, origS)
		}
		if i < 1 || i > 100 {
			return fmt.Errorf("percentage \"%s\" in \"%s\" must be an integer between 1 and 100", s, origS)
		}
		r.RefreshPercent = uint8(i)
	} else {
		dur, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("\"%s\" must be a valid time duration: %v", origS, err)
		}
		if dur < time.Duration(0) {
			return fmt.Errorf("\"%s\" must be a non-negative time duration", origS)
		}
		r.RefreshDuration = &dur
	}
	return nil
}
