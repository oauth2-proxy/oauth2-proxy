package ip

import (
	"net"
	"net/http"
)

// RealClientIPParser is an interface for a getting the client's real IP to be used for logging.
type RealClientIPParser interface {
	GetRealClientIP(http.Header) (net.IP, error)
}
