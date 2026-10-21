package redis

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/redis/go-redis/v9/auth"
)

const (
	// azureRedisScope is the Microsoft Entra ID scope of Azure Cache for Redis
	// and Azure Managed Redis
	azureRedisScope = "https://redis.azure.com/.default"

	// azureTokenPollInterval is how often the credential is asked for a token.
	// The credential returns its cached token and requests a new one 5 minutes
	// before it expires, or at half the lifetime of a managed identity token.
	azureTokenPollInterval = time.Minute

	// azureTokenRequestTimeout limits a single token request
	azureTokenRequestTimeout = 30 * time.Second
)

// newAzureCredential returns the credential of the Azure identity the proxy
// runs as: the workload identity when the Azure Workload Identity webhook has
// configured the environment, the managed identity of the host otherwise.
// Like azidentity.DefaultAzureCredential, it reads AZURE_CLIENT_ID to select a
// user-assigned managed identity. It is a variable so tests can replace it.
var newAzureCredential = func() (azcore.TokenCredential, error) {
	if os.Getenv("AZURE_FEDERATED_TOKEN_FILE") != "" {
		return azidentity.NewWorkloadIdentityCredential(nil)
	}

	opts := &azidentity.ManagedIdentityCredentialOptions{}
	if clientID := os.Getenv("AZURE_CLIENT_ID"); clientID != "" {
		opts.ID = azidentity.ClientID(clientID)
	}
	return azidentity.NewManagedIdentityCredential(opts)
}

// azureCredentialsProvider is a go-redis StreamingCredentialsProvider that
// authenticates with Microsoft Entra ID access tokens. Every connection
// subscribes to it and re-authenticates when a renewed token is published.
type azureCredentialsProvider struct {
	credential   azcore.TokenCredential
	pollInterval time.Duration

	// refreshMu serializes token requests with the publication of their
	// result, so connections always end up with the latest token
	refreshMu sync.Mutex

	mu          sync.Mutex
	token       azcore.AccessToken
	credentials auth.Credentials
	listeners   map[auth.CredentialsListener]struct{}
	polling     bool
}

func newAzureCredentialsProvider(credential azcore.TokenCredential, pollInterval time.Duration) *azureCredentialsProvider {
	return &azureCredentialsProvider{
		credential:   credential,
		pollInterval: pollInterval,
		listeners:    map[auth.CredentialsListener]struct{}{},
	}
}

// Subscribe returns the current credentials and publishes renewed credentials
// to the listener until it is unsubscribed.
func (p *azureCredentialsProvider) Subscribe(listener auth.CredentialsListener) (auth.Credentials, auth.UnsubscribeFunc, error) {
	if !p.hasValidToken() {
		if err := p.refresh(); err != nil {
			return nil, nil, err
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.listeners[listener] = struct{}{}
	if !p.polling {
		p.polling = true
		go p.poll()
	}

	unsubscribe := func() error {
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.listeners, listener)
		return nil
	}
	return p.credentials, unsubscribe, nil
}

// poll refreshes the token until no connection is subscribed.
func (p *azureCredentialsProvider) poll() {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		if len(p.listeners) == 0 {
			p.polling = false
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()

		// Connections keep the current token until it expires, so a failed
		// request is retried at the next tick.
		if err := p.refresh(); err != nil {
			logger.Errorf("Error renewing the Redis access token: %v", err)
		}
	}
}

// refresh requests a token and publishes it if it differs from the current one.
func (p *azureCredentialsProvider) refresh() error {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), azureTokenRequestTimeout)
	defer cancel()

	token, err := p.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureRedisScope}})
	if err != nil {
		return fmt.Errorf("unable to get a Microsoft Entra ID token for Redis: %w", err)
	}

	// Azure Redis expects the object ID of the identity as username
	objectID, err := tokenObjectID(token.Token)
	if err != nil {
		return err
	}
	credentials := auth.NewBasicCredentials(objectID, token.Token)

	p.mu.Lock()
	if token.Token == p.token.Token {
		p.mu.Unlock()
		return nil
	}
	p.token = token
	p.credentials = credentials
	listeners := make([]auth.CredentialsListener, 0, len(p.listeners))
	for listener := range p.listeners {
		listeners = append(listeners, listener)
	}
	p.mu.Unlock()

	for _, listener := range listeners {
		listener.OnNext(credentials)
	}
	return nil
}

func (p *azureCredentialsProvider) hasValidToken() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.credentials != nil && time.Now().Before(p.token.ExpiresOn)
}

// tokenObjectID returns the oid claim of an access token. The token is not
// verified: it was just issued to us and only Redis has to trust it.
func tokenObjectID(token string) (string, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return "", fmt.Errorf("unable to parse the Microsoft Entra ID token: %w", err)
	}
	objectID, _ := claims["oid"].(string)
	if objectID == "" {
		return "", errors.New("the Microsoft Entra ID token has no oid claim")
	}
	return objectID, nil
}

var _ auth.StreamingCredentialsProvider = (*azureCredentialsProvider)(nil)
