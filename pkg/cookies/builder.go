package cookies

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

type Builder interface {
	GetExpiration() time.Duration
	GetName() string
	MakeCookie(req *http.Request, value string) (*http.Cookie, error)
	ValidateRequest(req *http.Request) (string, error)
	ValidateCookie(requestCookie *http.Cookie) (string, error)
	WithExpiration(expiration time.Duration) Builder
	WithName(name string) Builder
	WithSignedValue(signed bool) Builder
	WithStart(start time.Time) Builder
}

type builder struct {
	name       string
	domains    []string
	path       string
	expiration time.Duration
	secure     bool
	httpOnly   bool
	sameSite   http.SameSite
	startTime  time.Time
	secret     string
	signValue  bool
}

func NewBuilder(opts options.Cookie) Builder {
	return builder{
		name:       opts.Name,
		domains:    opts.Domains,
		path:       opts.Path,
		expiration: opts.Expire,
		httpOnly:   opts.HTTPOnly,
		secure:     opts.Secure,
		sameSite:   ParseSameSite(opts.SameSite),
		secret:     opts.Secret,
	}
}

func (b builder) GetExpiration() time.Duration {
	return b.expiration
}

func (b builder) GetName() string {
	return b.name
}

func (b builder) WithExpiration(expiration time.Duration) Builder {
	b.expiration = expiration
	return b
}

func (b builder) WithName(name string) Builder {
	b.name = name
	return b
}

func (b builder) WithSignedValue(signed bool) Builder {
	b.signValue = signed
	return b
}

func (b builder) WithStart(start time.Time) Builder {
	b.startTime = start
	return b
}

func (b builder) MakeCookie(req *http.Request, value string) (*http.Cookie, error) {
	domain := b.getDomain(req)

	if b.signValue {
		var err error
		value, err = encryption.SignedValue(b.secret, b.name, []byte(value), b.start())
		if err != nil {
			return nil, fmt.Errorf("could not sign cookie value: %v", err)
		}
	}

	return &http.Cookie{
		Name:     b.name,
		Value:    value,
		Path:     b.path,
		Domain:   domain,
		HttpOnly: b.httpOnly,
		Secure:   b.secure,
		Expires:  b.start().Add(b.expiration),
		SameSite: b.sameSite,
	}, nil
}

func (b builder) ValidateRequest(req *http.Request) (string, error) {
	requestCookie, err := req.Cookie(b.name)
	if err != nil {
		return "", fmt.Errorf("cookie not found: %w", err)
	}

	return b.ValidateCookie(requestCookie)
}

func (b builder) ValidateCookie(requestCookie *http.Cookie) (string, error) {
	// An existing cookie exists, try to retrieve the ticket
	val, _, ok := encryption.Validate(requestCookie, b.secret, b.expiration)
	if !ok {
		return "", errors.New("cookie failed validation")
	}

	return string(val), nil
}

func (b builder) getDomain(req *http.Request) string {
	domain := GetCookieDomain(req, b.domains)
	if domain == "" && len(b.domains) > 0 {
		logger.Errorf("Warning: request host %q did not match any of the specific cookie domains of %q", requestutil.GetRequestHost(req), strings.Join(b.domains, ","))
		domain = b.domains[len(b.domains)-1]
	}

	if domain != "" {
		host := requestutil.GetRequestHost(req)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !strings.HasSuffix(host, domain) {
			logger.Errorf("Warning: request host is %q but using configured cookie domain of %q", host, domain)
		}
	}

	return domain
}

func (b builder) start() time.Time {
	if !b.startTime.IsZero() {
		return b.startTime
	}
	return time.Now()
}
