package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAWSIAMTokenGenerator(t *testing.T) {
	// Set up the environment, so we don't make any external calls to AWS
	t.Setenv("AWS_CONFIG_FILE", "file_not_exists")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "file_not_exists")
	t.Setenv("AWS_ENDPOINT_URL", "http://localhost:9999/aws")
	t.Setenv("AWS_ACCESS_KEY_ID", "access_key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret_key")
	t.Setenv("AWS_REGION", "us-east-1")

	tokenGenerator, err := New("elasticache", "test-cluster", "test-user")
	require.NotNil(t, tokenGenerator)
	require.NoError(t, err)

	token, err := tokenGenerator.GenerateToken()
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.Contains(t, token, "X-Amz-Algorithm", "signed token should contain algorithm attribute")
	require.Contains(t, token, "User=test-user", "signed token should contain user parameter")
	require.Contains(t, token, "X-Amz-Credential", "signed token should contain credential attribute")
	require.Contains(t, token, "X-Amz-Date", "signed token should contain date attribute")
	require.Contains(t, token, "X-Amz-Expires", "signed token should contain expires attribute")
	require.Contains(t, token, "X-Amz-SignedHeaders", "signed token should contain signed headers attribute")
	require.Contains(t, token, "X-Amz-Signature", "signed token should contain signature attribute")
	require.Contains(t, token, "Action=connect", "signed token should contain connect action")
	require.False(t, strings.HasPrefix(token, "http://"), "token should not have http:// scheme")
}
