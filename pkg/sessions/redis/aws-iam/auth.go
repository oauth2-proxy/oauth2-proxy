package auth

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
	"github.com/aws/aws-sdk-go-v2/config"
)

// This code was largely copied from this repo: https://github.com/build-on-aws/aws-redis-iam-auth-golang/tree/main

const (
	// "The IAM authentication token is valid for 15 minutes"
	// https://docs.aws.amazon.com/memorydb/latest/devguide/auth-iam.html#auth-iam-limits
	tokenValiditySeconds = 900

	connectAction = "connect"

	// If the request has no payload you should use the hex encoded SHA-256 of an empty string as the payloadHash value.
	hexEncodedSHA256EmptyString = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type TokenGenerator interface {
	GenerateToken() (string, error)
}

// IAMTokenGenerator generates an IAM token for AWS Redis authentication.
type iamTokenGenerator struct {
	serviceName string
	region      string
	req         *http.Request

	credentialsProvider aws.CredentialsProvider
	signer              *v4.Signer
}

// New creates a new IAMTokenGenerator instance
func New(serviceName, clusterName, userName string) (*IAMTokenGenerator, error) {

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)

	if err != nil {
		return nil, err
	}
	queryParams := url.Values{
		"Action":        {connectAction},
		"User":          {userName},
		"X-Amz-Expires": {strconv.FormatInt(int64(tokenValiditySeconds), 10)},
	}

	authURL := url.URL{
		Host:     clusterName,
		Scheme:   "http",
		Path:     "/",
		RawQuery: queryParams.Encode(),
	}

	req, err := http.NewRequest(http.MethodGet, authURL.String(), nil)

	if err != nil {
		return nil, err
	}

	return &iamTokenGenerator{
		serviceName:         serviceName,
		region:              cfg.Region,
		req:                 req,
		credentialsProvider: cfg.Credentials,
		signer:              v4.NewSigner(),
	}, nil
}

func (atg iamTokenGenerator) GenerateToken() (string, error) {
	ctx := context.Background()
	credentials, err := atg.credentialsProvider.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("AWS IAM credentials retrieval failed - %v", err)
	}
	signedURL, _, err := atg.signer.PresignHTTP(
		ctx,
		credentials,
		atg.req,
		hexEncodedSHA256EmptyString,
		atg.serviceName,
		atg.region,
		time.Now().UTC(),
	)

	if err != nil {
		return "", fmt.Errorf("AWS IAM request signing failed - %v", err)
	}
	// AWS expects the scheme to be removed before using as an auth token
	// https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/auth-iam.html#auth-iam-Connecting
	signedURL = strings.Replace(signedURL, "http://", "", 1)

	return signedURL, nil
}
