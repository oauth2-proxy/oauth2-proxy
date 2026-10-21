package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/auth"
)

const azureTestObjectID = "6f1d0c2e-1b4a-4c3e-9a57-3a8e2f0b7c11"

// fakeAzureCredential returns the token or error it was last given
type fakeAzureCredential struct {
	mu       sync.Mutex
	token    azcore.AccessToken
	err      error
	scopes   []string
	requests int
}

func (c *fakeAzureCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scopes = opts.Scopes
	c.requests++
	return c.token, c.err
}

func (c *fakeAzureCredential) requestCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests
}

func (c *fakeAzureCredential) set(token azcore.AccessToken, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token, c.err = token, err
}

func (c *fakeAzureCredential) requestedScopes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scopes
}

var testTokenID atomic.Int64

// newTestAccessToken returns a unique unsigned access token issued to objectID
func newTestAccessToken(objectID string, expiresIn time.Duration) azcore.AccessToken {
	expiresOn := time.Now().Add(expiresIn)
	claims := jwt.MapClaims{
		"exp": expiresOn.Unix(),
		"jti": fmt.Sprint(testTokenID.Add(1)),
	}
	if objectID != "" {
		claims["oid"] = objectID
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	Expect(err).ToNot(HaveOccurred())
	return azcore.AccessToken{Token: token, ExpiresOn: expiresOn}
}

// passwordRecorder records passwords for concurrent tests
type passwordRecorder struct {
	mu        sync.Mutex
	passwords []string
}

func (r *passwordRecorder) record(password string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.passwords = append(r.passwords, password)
}

func (r *passwordRecorder) received() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.passwords...)
}

// recordingListener records the passwords of the credentials published to it
type recordingListener struct {
	passwordRecorder
}

func (l *recordingListener) OnNext(credentials auth.Credentials) {
	_, password := credentials.BasicAuth()
	l.record(password)
}

func (l *recordingListener) OnError(error) {}

// slowListener records the passwords of the credentials published to it, and
// blocks the first publication until it is released, like a slow
// re-authentication
type slowListener struct {
	passwordRecorder
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (l *slowListener) OnNext(credentials auth.Credentials) {
	if l.calls.Add(1) == 1 {
		close(l.entered)
		<-l.release
	}
	_, password := credentials.BasicAuth()
	l.record(password)
}

func (l *slowListener) OnError(error) {}

// unsubscribingListener unsubscribes when the first credentials are published
// to it, like a connection that closes while it re-authenticates
type unsubscribingListener struct {
	passwordRecorder
	unsubscribe auth.UnsubscribeFunc
}

func (l *unsubscribingListener) OnNext(credentials auth.Credentials) {
	_, password := credentials.BasicAuth()
	l.record(password)
	Expect(l.unsubscribe()).To(Succeed())
}

func (l *unsubscribingListener) OnError(error) {}

// authRecorder is a redis.Hook that records the passwords sent with AUTH
type authRecorder struct {
	passwordRecorder
}

func (r *authRecorder) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (r *authRecorder) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if args := cmd.Args(); strings.EqualFold(cmd.Name(), "auth") && len(args) == 3 {
			r.record(fmt.Sprint(args[2]))
		}
		return next(ctx, cmd)
	}
}

func (r *authRecorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

var _ = Describe("Azure credential", func() {
	It("is the workload identity when the Azure Workload Identity webhook has configured the environment", func() {
		GinkgoT().Setenv("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token")
		GinkgoT().Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000001")
		GinkgoT().Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000002")

		credential, err := newAzureCredential()
		Expect(err).ToNot(HaveOccurred())
		Expect(credential).To(BeAssignableToTypeOf(&azidentity.WorkloadIdentityCredential{}))
	})

	It("is the managed identity of the host otherwise", func() {
		GinkgoT().Setenv("AZURE_FEDERATED_TOKEN_FILE", "")

		credential, err := newAzureCredential()
		Expect(err).ToNot(HaveOccurred())
		Expect(credential).To(BeAssignableToTypeOf(&azidentity.ManagedIdentityCredential{}))
	})
})

var _ = Describe("Azure managed identity credentials provider", func() {
	var credential *fakeAzureCredential
	var token azcore.AccessToken
	var provider *azureCredentialsProvider

	BeforeEach(func() {
		token = newTestAccessToken(azureTestObjectID, time.Hour)
		credential = &fakeAzureCredential{token: token}
		provider = newAzureCredentialsProvider(credential, 10*time.Millisecond)
	})

	It("authenticates with the object ID and the access token of the identity", func() {
		credentials, unsubscribe, err := provider.Subscribe(&recordingListener{})
		Expect(err).ToNot(HaveOccurred())
		defer unsubscribe()

		username, password := credentials.BasicAuth()
		Expect(username).To(Equal(azureTestObjectID))
		Expect(password).To(Equal(token.Token))
		Expect(credential.requestedScopes()).To(ConsistOf("https://redis.azure.com/.default"))
	})

	It("publishes renewed tokens to subscribed connections", func() {
		subscribed := &recordingListener{}
		_, unsubscribe, err := provider.Subscribe(subscribed)
		Expect(err).ToNot(HaveOccurred())
		defer unsubscribe()

		unsubscribed := &recordingListener{}
		_, unsubscribeOther, err := provider.Subscribe(unsubscribed)
		Expect(err).ToNot(HaveOccurred())
		Expect(unsubscribeOther()).To(Succeed())

		renewed := newTestAccessToken(azureTestObjectID, 2*time.Hour)
		credential.set(renewed, nil)

		Eventually(subscribed.received).Should(Equal([]string{renewed.Token}))
		Expect(unsubscribed.received()).To(BeEmpty())
	})

	It("keeps using the current token while renewals fail", func() {
		_, unsubscribe, err := provider.Subscribe(&recordingListener{})
		Expect(err).ToNot(HaveOccurred())
		defer unsubscribe()

		credential.set(azcore.AccessToken{}, errors.New("identity endpoint unavailable"))
		Expect(provider.refresh()).To(MatchError(ContainSubstring("identity endpoint unavailable")))

		credentials, unsubscribeOther, err := provider.Subscribe(&recordingListener{})
		Expect(err).ToNot(HaveOccurred())
		defer unsubscribeOther()
		_, password := credentials.BasicAuth()
		Expect(password).To(Equal(token.Token))
	})

	It("publishes the next token after failed renewals", func() {
		subscribed := &recordingListener{}
		_, unsubscribe, err := provider.Subscribe(subscribed)
		Expect(err).ToNot(HaveOccurred())
		defer unsubscribe()

		credential.set(azcore.AccessToken{}, errors.New("identity endpoint unavailable"))
		Consistently(subscribed.received, 100*time.Millisecond).Should(BeEmpty())

		renewed := newTestAccessToken(azureTestObjectID, 2*time.Hour)
		credential.set(renewed, nil)
		Eventually(subscribed.received).Should(Equal([]string{renewed.Token}))
	})

	It("publishes a new token with the same expiry", func() {
		subscribed := &recordingListener{}
		_, unsubscribe, err := provider.Subscribe(subscribed)
		Expect(err).ToNot(HaveOccurred())
		defer unsubscribe()

		renewed := newTestAccessToken(azureTestObjectID, time.Hour)
		renewed.ExpiresOn = token.ExpiresOn
		credential.set(renewed, nil)
		Eventually(subscribed.received).Should(Equal([]string{renewed.Token}))
	})

	It("publishes tokens in the order they were requested", func() {
		provider = newAzureCredentialsProvider(credential, time.Hour)
		listener := &slowListener{entered: make(chan struct{}), release: make(chan struct{})}
		_, unsubscribe, err := provider.Subscribe(listener)
		Expect(err).ToNot(HaveOccurred())
		defer unsubscribe()

		first := newTestAccessToken(azureTestObjectID, 2*time.Hour)
		credential.set(first, nil)
		errs := make(chan error, 2)
		go func() { errs <- provider.refresh() }()
		Eventually(listener.entered).Should(BeClosed())

		// Renew again while the first token is still being published
		second := newTestAccessToken(azureTestObjectID, 3*time.Hour)
		credential.set(second, nil)
		go func() { errs <- provider.refresh() }()
		Consistently(listener.received, 100*time.Millisecond).Should(BeEmpty())

		close(listener.release)
		Eventually(errs).Should(Receive(BeNil()))
		Eventually(errs).Should(Receive(BeNil()))
		Expect(listener.received()).To(Equal([]string{first.Token, second.Token}))
	})

	It("fails to authenticate without a valid token", func() {
		credential.set(azcore.AccessToken{}, errors.New("identity endpoint unavailable"))

		_, _, err := provider.Subscribe(&recordingListener{})
		Expect(err).To(MatchError(ContainSubstring("identity endpoint unavailable")))
	})

	It("rejects tokens without an object ID", func() {
		credential.set(newTestAccessToken("", time.Hour), nil)

		_, _, err := provider.Subscribe(&recordingListener{})
		Expect(err).To(MatchError("the Microsoft Entra ID token has no oid claim"))
	})

	It("stops polling when no connection is subscribed", func() {
		_, unsubscribe, err := provider.Subscribe(&recordingListener{})
		Expect(err).ToNot(HaveOccurred())
		Expect(unsubscribe()).To(Succeed())

		Eventually(func() bool {
			provider.mu.Lock()
			defer provider.mu.Unlock()
			return provider.polling
		}).Should(BeFalse())
	})

	It("lets a connection unsubscribe while a token is published to it", func() {
		provider = newAzureCredentialsProvider(credential, time.Hour)
		listener := &unsubscribingListener{}
		_, unsubscribe, err := provider.Subscribe(listener)
		Expect(err).ToNot(HaveOccurred())
		listener.unsubscribe = unsubscribe

		renewed := newTestAccessToken(azureTestObjectID, 2*time.Hour)
		credential.set(renewed, nil)
		Expect(provider.refresh()).To(Succeed())

		credential.set(newTestAccessToken(azureTestObjectID, 3*time.Hour), nil)
		Expect(provider.refresh()).To(Succeed())
		Expect(listener.received()).To(Equal([]string{renewed.Token}))
	})

	It("stops polling after concurrent subscriptions, unsubscriptions and renewals", func() {
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for j := 0; j < 20; j++ {
					_, unsubscribe, err := provider.Subscribe(&recordingListener{})
					Expect(err).ToNot(HaveOccurred())
					Expect(unsubscribe()).To(Succeed())
				}
			}()
		}
		for i := 1; i <= 20; i++ {
			credential.set(newTestAccessToken(azureTestObjectID, time.Hour+time.Duration(i)*time.Minute), nil)
			Expect(provider.refresh()).To(Succeed())
		}
		wg.Wait()

		Eventually(func() bool {
			provider.mu.Lock()
			defer provider.mu.Unlock()
			return provider.polling || len(provider.listeners) > 0
		}).Should(BeFalse())
		requests := credential.requestCount()
		Consistently(credential.requestCount, 100*time.Millisecond).Should(Equal(requests))
	})
})

var _ = Describe("Redis SessionStore with Azure managed identity", func() {
	const redissProtocol = "rediss://"

	var mr *miniredis.Miniredis
	var ss sessionsapi.SessionStore
	var credential *fakeAzureCredential
	var originalNewAzureCredential func() (azcore.TokenCredential, error)

	BeforeEach(func() {
		var err error
		mr, err = miniredis.RunTLS(&tls.Config{Certificates: []tls.Certificate{cert}})
		Expect(err).ToNot(HaveOccurred())

		// Like Azure Redis, accept only the current token of the identity
		token := newTestAccessToken(azureTestObjectID, time.Hour)
		mr.RequireUserAuth(azureTestObjectID, token.Token)
		credential = &fakeAzureCredential{token: token}

		originalNewAzureCredential = newAzureCredential
		newAzureCredential = func() (azcore.TokenCredential, error) {
			return credential, nil
		}
	})

	AfterEach(func() {
		newAzureCredential = originalNewAzureCredential
		mr.Close()
	})

	JustAfterEach(func() {
		// Release any connections immediately after the test ends
		if redisManager, ok := ss.(*persistence.Manager); ok {
			if redisManager.Store.(*SessionStore).Client != nil {
				Expect(redisManager.Store.(*SessionStore).Client.(io.Closer).Close()).To(Succeed())
			}
		}
	})

	Context("with standalone", func() {
		tests.RunSessionStoreTests(
			func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
				opts.Type = options.RedisSessionStoreType
				opts.Redis.ConnectionURL = redissProtocol + mr.Addr()
				opts.Redis.CAPath = caPath
				opts.Redis.CredentialsProvider = options.AzureManagedIdentityRedisCredentialsProvider

				// Capture the session store so that we can close the client
				var err error
				ss, err = NewRedisSessionStore(opts, cookieOpts)
				return ss, err
			},
			func(d time.Duration) error {
				mr.FastForward(d)
				return nil
			},
		)
	})

	Context("with cluster", func() {
		tests.RunSessionStoreTests(
			func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
				opts.Type = options.RedisSessionStoreType
				opts.Redis.ClusterConnectionURLs = []string{redissProtocol + mr.Addr()}
				opts.Redis.UseCluster = true
				opts.Redis.CAPath = caPath
				opts.Redis.CredentialsProvider = options.AzureManagedIdentityRedisCredentialsProvider

				// Capture the session store so that we can close the client
				var err error
				ss, err = NewRedisSessionStore(opts, cookieOpts)
				return ss, err
			},
			func(d time.Duration) error {
				mr.FastForward(d)
				return nil
			},
		)
	})

	It("re-authenticates open connections with a renewed token", func() {
		redisClient, err := NewRedisClient(options.RedisStoreOptions{
			ConnectionURL:       redissProtocol + mr.Addr(),
			CAPath:              caPath,
			CredentialsProvider: options.AzureManagedIdentityRedisCredentialsProvider,
		})
		Expect(err).ToNot(HaveOccurred())
		rc := redisClient.(*client)
		defer rc.Close()
		auths := &authRecorder{}
		rc.AddHook(auths)

		ctx := context.Background()
		Expect(rc.Set(ctx, "key", []byte("value"), time.Minute)).To(Succeed())

		renewed := newTestAccessToken(azureTestObjectID, 2*time.Hour)
		mr.RequireUserAuth(azureTestObjectID, renewed.Token)
		credential.set(renewed, nil)
		Expect(rc.Options().StreamingCredentialsProvider.(*azureCredentialsProvider).refresh()).To(Succeed())

		Expect(rc.Get(ctx, "key")).To(Equal([]byte("value")))
		Eventually(auths.received).Should(ContainElement(renewed.Token))
	})

	DescribeTable("rejects unsupported configurations",
		func(opts options.RedisStoreOptions, expectedError string) {
			if opts.CredentialsProvider == "" {
				opts.CredentialsProvider = options.AzureManagedIdentityRedisCredentialsProvider
			}
			_, err := NewRedisClient(opts)
			Expect(err).To(MatchError(expectedError))
		},
		Entry("with Sentinel",
			options.RedisStoreOptions{
				UseSentinel:            true,
				SentinelConnectionURLs: []string{"rediss://localhost:26379"},
			},
			"option redis-credentials-provider is not supported with redis-use-sentinel",
		),
		Entry("without TLS",
			options.RedisStoreOptions{ConnectionURL: "redis://localhost:6379"},
			`redis credentials provider "azure-managed-identity" requires a TLS connection with certificate verification`,
		),
		Entry("without TLS certificate verification",
			options.RedisStoreOptions{ConnectionURL: "redis://localhost:6380", InsecureSkipTLSVerify: true},
			`redis credentials provider "azure-managed-identity" requires a TLS connection with certificate verification`,
		),
		Entry("without TLS certificate verification in the URL",
			options.RedisStoreOptions{ConnectionURL: "rediss://localhost:6380?skip_verify=true"},
			`redis credentials provider "azure-managed-identity" requires a TLS connection with certificate verification`,
		),
		Entry("with a password",
			options.RedisStoreOptions{ConnectionURL: "rediss://localhost:6380", Password: redisPassword},
			`redis credentials provider "azure-managed-identity" cannot be used with a redis username or password`,
		),
		Entry("with credentials in one of the cluster URLs",
			options.RedisStoreOptions{
				UseCluster: true,
				ClusterConnectionURLs: []string{
					"rediss://" + redisUsername + ":" + redisPassword + "@localhost:6380",
					"rediss://localhost:6381",
				},
			},
			`redis credentials provider "azure-managed-identity" cannot be used with a redis username or password`,
		),
		Entry("with an unknown provider",
			options.RedisStoreOptions{ConnectionURL: "rediss://localhost:6380", CredentialsProvider: "unknown"},
			`unknown redis credentials provider "unknown"`,
		),
	)
})
