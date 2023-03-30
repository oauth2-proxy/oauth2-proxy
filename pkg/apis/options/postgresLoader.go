package options

import (
	"fmt"
	"time"
)

type PostgresLoader struct {
	Postgres Postgres
	Redis    Redis
	API      API
}

type API struct {
	Host       string
	Port       int
	PathPrefix string
	Timeout    time.Duration
}

type Redis struct {
	RedisStoreOptions `mapstructure:",squash"`
	Expiry            time.Duration
	Prefix            string
}

type Postgres struct {
	Host           string
	Port           uint16
	Database       string
	Schema         string
	User           string
	Password       string
	MaxConnections int
	SslMode        string
	SslRootCert    string
	SslCrl         string
	SslCert        string
	SslKey         string
}

func (c *Postgres) ConnectionString() string {
	return fmt.Sprintf("port=%v host=%s user=%s password=%s dbname=%s search_path=%s sslmode=%s sslrootcert=%s sslcrl=%s sslcert=%s sslkey=%s", c.Port, c.Host, c.User, c.Password, c.Database, c.Schema, c.SslMode, c.SslRootCert, c.SslCrl, c.SslCert, c.SslKey)
}
