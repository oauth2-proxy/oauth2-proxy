package redis

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	elasticacheServiceName = "elasticache"
	connectAction          = "connect"
	tokenExpirySeconds     = 900 // 15 minutes
	// SHA-256 hash of an empty string, required by SigV4 PresignHTTP.
	emptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// iamTokenGenerator generates short-lived IAM auth tokens for ElastiCache
// by SigV4-presigning a request. Each call to Generate produces a fresh token.
type iamTokenGenerator struct {
	userID             string
	replicationGroupID string
	region             string
	serverless         bool
	credentials        aws.CredentialsProvider
}

// Generate creates a new IAM auth token by SigV4 presigning a synthetic
// HTTP request. The returned string is used as the Redis AUTH password.
func (g *iamTokenGenerator) Generate(ctx context.Context) (string, error) {
	u, err := url.Parse(fmt.Sprintf("http://%s/", g.replicationGroupID))
	if err != nil {
		return "", fmt.Errorf("failed to build IAM token URL: %w", err)
	}

	query := u.Query()
	query.Set("Action", connectAction)
	query.Set("User", g.userID)
	if g.serverless {
		query.Set("ResourceType", "ServerlessCache")
	}
	query.Set("X-Amz-Expires", strconv.Itoa(tokenExpirySeconds))
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create IAM token request: %w", err)
	}

	creds, err := g.credentials.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}

	signer := v4.NewSigner()
	uri, _, err := signer.PresignHTTP(ctx, creds, req, emptyBodySHA256, elasticacheServiceName, g.region, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to presign IAM token: %w", err)
	}

	// The auth token is the presigned URL without the "http://" prefix.
	return strings.TrimPrefix(uri, "http://"), nil
}
