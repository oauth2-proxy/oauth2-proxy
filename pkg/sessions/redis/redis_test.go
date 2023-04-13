package redis_test

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"
)

// wrappedRedisLogger wraps a logger so that we can coerce the logger to
// fit the expected signature for go-redis logging
type wrappedRedisLogger struct {
	*log.Logger
}

func (l *wrappedRedisLogger) Printf(_ context.Context, format string, v ...interface{}) {
	l.Logger.Printf(format, v...)
}

func TestRedis(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	redisLogger := &wrappedRedisLogger{Logger: log.New(os.Stderr, "redis: ", log.LstdFlags|log.Lshortfile)}
	redisLogger.SetOutput(GinkgoWriter)
	redis.SetLogger(redisLogger)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Redis")
}
