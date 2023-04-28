package options

import (
	"fmt"
	"time"
)

type PostgresLoader struct {

	// Postgres defines the configuration of Postgres DB store.
	Postgres Postgres

	// Redis defines the configuration of Redis DB which is used as a cache.
	Redis Redis

	// API defines configuration of API exposed for CURD operations
	// on the configuration store.
	API API
}

type API struct {

	// Name of the host.
	Host string

	// Port of the host.
	Port int

	// PathPrefix is an optional prefix that will be
	// prepended to the API path if it is non-empty.
	// Default is set to options.ProxyPrefix which is set to "/oauth2" by default.
	PathPrefix string

	// HandlerTimeout is the time duration value
	// after which the API will timeout.
	HandlerTimeout time.Duration

	// ReadHeaderTimeout is the time.duration allowed
	// to read request header. If not set a default value of
	// 10 seconds is used.
	ReadHeaderTimeout time.Duration
}

type Redis struct {

	// RedisStoreOptions reperesent the configuration
	// of a redis store.
	RedisStoreOptions `mapstructure:",squash"`

	// Expiry time is the time duration after which a data entry
	// added in redis cache will be deleted.
	Expiry time.Duration

	// Prefix is the string which is prepended to each key
	// in redis store.
	Prefix string
}

type Postgres struct {

	// Host is the name of the postgres host.
	Host string

	// Post is the host port.
	Port uint16

	// Database defines the database name in Postgres Store.
	Database string

	// Schema defines the schema in Postgres.
	Schema string

	// User contains the username for connecting to Postgres.
	User string

	// Password contains the password for connecting with Postgres.
	Password string

	// MaxConnections is the number of maxmimum connections allowed.
	MaxConnections int

	// SslMode defines the ssl security mode.This option determines whether or with what priority a secure SSL TCP/IP
	// connection will be negotiated with the server. There are six modes:
	//
	// disable: only try a non-SSL connection
	// allow:first try a non-SSL connection; if that fails, try an SSL connection
	// prefer (default): first try an SSL connection; if that fails, try a non-SSL connection
	// require: only try an SSL connection. If a root CA file is present, verify the certificate in the same way as if verify-ca was specified
	// verify-ca: only try an SSL connection, and verify that the server certificate is issued by a trusted certificate authority (CA)
	// verify-full: only try an SSL connection, verify that the server certificate is issued by a trusted CA and that the requested server host name matches that in the certificate
	SslMode string

	// This parameter specifies the name of a file containing SSL certificate authority (CA) certificate(s).
	// If the file exists, the server's certificate will be verified to be signed by one of these authorities.
	SslRootCert string

	// This parameter specifies the file name of the SSL server certificate revocation list (CRL). Certificates listed in this file, if it exists,
	// will be rejected while attempting to authenticate the server's certificate.
	SslCrl string

	// This parameter specifies the file name of the client SSL certificate. This parameter is ignored if an SSL connection is not made.
	SslCert string

	// This parameter specifies the location for the secret key used for the client certificate.
	// It can either specify a file name, or it can specify a key obtained from an external “engine” (engines are OpenSSL loadable modules). An external engine specification should consist of a colon-separated engine name and an engine-specific key identifier.
	// This parameter is ignored if an SSL connection is not made.
	SslKey string
}

func (c *Postgres) ConnectionString() string {
	return fmt.Sprintf("port=%v host=%s user=%s password=%s dbname=%s search_path=%s sslmode=%s sslrootcert=%s sslcrl=%s sslcert=%s sslkey=%s", c.Port, c.Host, c.User, c.Password, c.Database, c.Schema, c.SslMode, c.SslRootCert, c.SslCrl, c.SslCert, c.SslKey)
}
