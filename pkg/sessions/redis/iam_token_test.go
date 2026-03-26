package redis

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticCredentials implements aws.CredentialsProvider with fixed test values.
type staticCredentials struct{}

func (s staticCredentials) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "test-session-token",
		Source:          "test",
		CanExpire:       true,
		Expires:         time.Now().Add(1 * time.Hour),
	}, nil
}

func TestIAMTokenGenerator_Generate(t *testing.T) {
	gen := &iamTokenGenerator{
		userID:             "my-user",
		replicationGroupID: "my-cluster",
		region:             "us-east-1",
		credentials:        staticCredentials{},
	}

	token, err := gen.Generate(context.Background())
	require.NoError(t, err)

	// The token should not have the http:// prefix
	assert.False(t, strings.HasPrefix(token, "http://"))

	// The token must start with the replication group ID
	assert.True(t, strings.HasPrefix(token, "my-cluster/"))

	// The token must contain the required query parameters
	assert.Contains(t, token, "Action=connect")
	assert.Contains(t, token, "User=my-user")
	assert.Contains(t, token, "X-Amz-Expires=900")

	// Non-serverless tokens must NOT contain ResourceType
	assert.NotContains(t, token, "ResourceType")

	// SigV4 signature fields
	assert.Contains(t, token, "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, token, "X-Amz-Signature=")
	assert.Contains(t, token, "X-Amz-Security-Token=test-session-token")
	assert.Contains(t, token, "X-Amz-SignedHeaders=host")
}

func TestIAMTokenGenerator_Generate_Serverless(t *testing.T) {
	gen := &iamTokenGenerator{
		userID:             "my-user",
		replicationGroupID: "my-cache",
		region:             "us-east-1",
		serverless:         true,
		credentials:        staticCredentials{},
	}

	token, err := gen.Generate(context.Background())
	require.NoError(t, err)

	assert.False(t, strings.HasPrefix(token, "http://"))
	assert.True(t, strings.HasPrefix(token, "my-cache/"))
	assert.Contains(t, token, "Action=connect")
	assert.Contains(t, token, "User=my-user")
	assert.Contains(t, token, "ResourceType=ServerlessCache")
	assert.Contains(t, token, "X-Amz-Expires=900")
	assert.Contains(t, token, "X-Amz-Signature=")
}
