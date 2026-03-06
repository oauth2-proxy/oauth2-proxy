package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	sessions_redis "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/redis"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDpop(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "DPoP Suite")
}

var (
	testPrivateKey *ecdsa.PrivateKey
	testJWK        jose.JSONWebKey
)

var _ = BeforeSuite(func() {
	var err error
	testPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())

	testJWK = jose.JSONWebKey{
		Key:       &testPrivateKey.PublicKey,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
})

// testDpopOpts customize DPoP proof generation for testing
type testDpopOpts struct {
	Method      string
	URI         string
	AccessToken string

	InitSignerOpts func(opts *jose.SignerOptions, jwk jose.JSONWebKey)
	MutateClaims   func(*claims)
	InvalidSig     bool
}

func generateTestDpop(opts testDpopOpts) string {
	signerOpts := &jose.SignerOptions{}
	if opts.InitSignerOpts != nil {
		opts.InitSignerOpts(signerOpts, testJWK)
	} else {
		signerOpts.WithType("dpop+jwt")
		signerOpts.WithHeader("jwk", testJWK)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: testPrivateKey},
		signerOpts,
	)
	Expect(err).ToNot(HaveOccurred())

	ath := ""
	if opts.AccessToken != "" {
		ath = CalcATH(opts.AccessToken)
	}

	c := claims{
		JTI: uuid.New().String(),
		HTM: opts.Method,
		HTU: opts.URI,
		IAT: time.Now().Unix(),
		ATH: ath,
	}

	if opts.MutateClaims != nil {
		opts.MutateClaims(&c)
	}

	payload, err := json.Marshal(c)
	Expect(err).ToNot(HaveOccurred())

	jws, err := signer.Sign(payload)
	Expect(err).ToNot(HaveOccurred())

	serialized, err := jws.CompactSerialize()
	Expect(err).ToNot(HaveOccurred())

	if opts.InvalidSig {
		mid := len(serialized) / 2
		serialized = serialized[:mid] + "X" + serialized[mid+1:]
	}

	return serialized
}

var _ = Describe("DPoP", func() {
	Describe("Factory", func() {
		var opts *options.Options

		BeforeEach(func() {
			opts = options.NewOptions()
			opts.DPoP.Enable = true
		})

		It("should return nil if DPoP is disabled", func() {
			opts.DPoP.Enable = false
			store, err := NewDpopStore(opts)
			Expect(err).ToNot(HaveOccurred())
			Expect(store).To(BeNil())
		})

		It("should return a memory store if specifically configured", func() {
			opts.DPoP.JtiStoreType = "memory"
			store, err := NewDpopStore(opts)
			Expect(err).ToNot(HaveOccurred())
			Expect(store).To(BeAssignableToTypeOf(&MemoryDpopStore{}))
		})

		It("should return a memory store by default if session type is not redis", func() {
			opts.Session.Type = "cookie"
			opts.DPoP.JtiStoreType = ""
			store, err := NewDpopStore(opts)
			Expect(err).ToNot(HaveOccurred())
			Expect(store).To(BeAssignableToTypeOf(&MemoryDpopStore{}))
		})

		It("should return a redis store with session config if session type is redis and no type is specified", func() {
			opts.Session.Type = "redis"
			opts.Session.Redis.ConnectionURL = "redis://host:1234"
			opts.DPoP.JtiStoreType = ""
			store, err := NewDpopStore(opts)
			Expect(err).ToNot(HaveOccurred())
			Expect(store).To(BeAssignableToTypeOf(&RedisDpopStore{}))
		})

		It("should return a redis store with session config if specifically configured as session-redis", func() {
			opts.Session.Type = "cookie"
			opts.Session.Redis.ConnectionURL = "redis://host:1234"
			opts.DPoP.JtiStoreType = "session-redis"
			store, err := NewDpopStore(opts)
			Expect(err).ToNot(HaveOccurred())
			Expect(store).To(BeAssignableToTypeOf(&RedisDpopStore{}))
		})

		It("should return an error for an unknown store type", func() {
			opts.DPoP.JtiStoreType = "unknown"
			store, err := NewDpopStore(opts)
			Expect(err).To(HaveOccurred())
			Expect(store).To(BeNil())
		})
	})

	Describe("Store", func() {
		Context("Memory Store", func() {
			var store *MemoryDpopStore

			BeforeEach(func() {
				store = NewMemoryDpopStore()
			})

			RunStoreTests(func() DpopStore {
				return NewMemoryDpopStore()
			}, func(d time.Duration) {
				time.Sleep(d)
			})

			It("should perform CleanUp", func() {
				ctx := context.Background()
				_, _ = store.MarkJtiSeen(ctx, "jkt", "jti-short", time.Now().Add(5*time.Millisecond))
				_, _ = store.MarkJtiSeen(ctx, "jkt", "jti-long", time.Now().Add(1*time.Minute))

				Expect(store.entries).To(HaveLen(2))
				time.Sleep(10 * time.Millisecond)
				store.CleanUp()

				Expect(store.entries).To(HaveLen(1))
				Expect(store.entries).To(HaveKey("jkt:jti-long"))
			})

			It("should perform preemptive CleanUp", func() {
				ctx := context.Background()
				_, _ = store.MarkJtiSeen(ctx, "jkt", "jti-expire", time.Now().Add(10*time.Millisecond))
				Expect(store.dirty).To(BeTrue())
				Expect(store.entries).To(HaveLen(1))

				time.Sleep(20 * time.Millisecond)
				store.lastCleanup = time.Now().Add(-2 * time.Minute)

				_, _ = store.MarkJtiSeen(ctx, "jkt", "jti-new", time.Now().Add(1*time.Minute))

				Expect(store.entries).To(HaveLen(1))
				Expect(store.entries).To(HaveKey("jkt:jti-new"))
				Expect(store.entries).ToNot(HaveKey("jkt:jti-expire"))

				Expect(store.dirty).To(BeTrue())
				Expect(store.lastCleanup).To(BeTemporally("~", time.Now(), time.Second))
			})
		})

		Context("Redis Store", func() {
			var mr *miniredis.Miniredis

			BeforeEach(func() {
				var err error
				mr, err = miniredis.Run()
				Expect(err).ToNot(HaveOccurred())
			})

			AfterEach(func() {
				if mr != nil {
					mr.Close()
				}
			})

			getStore := func() DpopStore {
				client, err := sessions_redis.NewRedisClient(options.RedisStoreOptions{
					ConnectionURL: "redis://" + mr.Addr(),
				})
				Expect(err).ToNot(HaveOccurred())
				return NewRedisDpopStore(client)
			}

			RunStoreTests(getStore, func(d time.Duration) {
				mr.FastForward(d)
			})

			It("should handle expiration correctly in Redis", func() {
				store := getStore()
				ctx := context.Background()

				added, err := store.MarkJtiSeen(ctx, "jkt", "jti-expire", time.Now().Add(1*time.Minute))
				Expect(err).ToNot(HaveOccurred())
				Expect(added).To(BeTrue())

				added, err = store.MarkJtiSeen(ctx, "jkt", "jti-expire", time.Now().Add(1*time.Minute))
				Expect(err).ToNot(HaveOccurred())
				Expect(added).To(BeFalse())

				mr.FastForward(2 * time.Minute)
				time.Sleep(10 * time.Millisecond)

				added, err = store.MarkJtiSeen(ctx, "jkt", "jti-expire", time.Now().Add(1*time.Minute))
				Expect(err).ToNot(HaveOccurred())
				Expect(added).To(BeTrue())
			})

			It("should allow same JTI for different JKTs", func() {
				store := getStore()
				ctx := context.Background()
				jti := "common-jti"

				added, err := store.MarkJtiSeen(ctx, "jkt-1", jti, time.Now().Add(1*time.Minute))
				Expect(err).ToNot(HaveOccurred())
				Expect(added).To(BeTrue())

				added, err = store.MarkJtiSeen(ctx, "jkt-2", jti, time.Now().Add(1*time.Minute))
				Expect(err).ToNot(HaveOccurred())
				Expect(added).To(BeTrue())

				added, err = store.MarkJtiSeen(ctx, "jkt-1", jti, time.Now().Add(1*time.Minute))
				Expect(err).ToNot(HaveOccurred())
				Expect(added).To(BeFalse())
			})
		})
	})

	Describe("Validator", func() {
		validMethod := "POST"
		validURI := "https://server.example.com/resource"
		validToken := "my-access-token"

		DescribeTable("Validate proof structured tests",
			func(reqSetup func() *http.Request, accessToken string, expectErrMsgContains string) {
				req := reqSetup()
				validator := NewDpopValidator(options.DefaultDpopTimeWindow, nil)
				thumbprint, err := validator.ValidateDPopToken(req, accessToken)

				if expectErrMsgContains != "" {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(expectErrMsgContains))
					Expect(thumbprint).To(BeEmpty())
				} else {
					Expect(err).ToNot(HaveOccurred())
					Expect(thumbprint).ToNot(BeEmpty())
				}
			},
			Entry("Valid Proof with Access Token", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{Method: validMethod, URI: validURI, AccessToken: validToken})
				req.Header.Add("DPoP", proof)
				return req
			}, validToken, ""),
			Entry("Valid Proof without Access Token", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{Method: validMethod, URI: validURI})
				req.Header.Add("DPoP", proof)
				return req
			}, "", ""),
			Entry("Missing DPoP Header", func() *http.Request {
				return httptest.NewRequest(validMethod, validURI, nil)
			}, "", "missing DPoP header"),
			Entry("Invalid JWT Structure", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				req.Header.Add("DPoP", "not-a-jwt")
				return req
			}, "", "failed to parse DPoP JWS"),
			Entry("Invalid Signature", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{Method: validMethod, URI: validURI, InvalidSig: true})
				req.Header.Add("DPoP", proof)
				return req
			}, "", "invalid or missing typ header claim"),
			Entry("Missing jwk header", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{
					Method: validMethod,
					URI:    validURI,
					InitSignerOpts: func(so *jose.SignerOptions, jwk jose.JSONWebKey) {
						so.WithType("dpop+jwt")
					},
				})
				req.Header.Add("DPoP", proof)
				return req
			}, "", "missing jwk header claim"),
			Entry("jwk with invalid key type", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{
					Method: validMethod,
					URI:    validURI,
					InitSignerOpts: func(so *jose.SignerOptions, jwk jose.JSONWebKey) {
						so.WithType("dpop+jwt")
						so.WithHeader("jwk", jose.JSONWebKey{Key: []byte("not-a-key"), Use: "sig"})
					},
				})
				req.Header.Add("DPoP", proof)
				return req
			}, "", "failed to parse DPoP JWS"),
			Entry("Invalid HTM claim", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{
					Method: validMethod,
					URI:    validURI,
					MutateClaims: func(c *claims) {
						c.HTM = "GET"
					},
				})
				req.Header.Add("DPoP", proof)
				return req
			}, "", "htm claim"),
			Entry("Invalid HTU claim", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{
					Method: validMethod,
					URI:    validURI,
					MutateClaims: func(c *claims) {
						c.HTU = "https://wrong.com"
					},
				})
				req.Header.Add("DPoP", proof)
				return req
			}, "", "htu claim"),
			Entry("Invalid ATH claim", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{
					Method:      validMethod,
					URI:         validURI,
					AccessToken: "wrong-token",
				})
				req.Header.Add("DPoP", proof)
				return req
			}, validToken, "ath claim"),
			Entry("Missing ATH claim when token present", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{Method: validMethod, URI: validURI})
				req.Header.Add("DPoP", proof)
				return req
			}, validToken, "missing ath claim"),
			Entry("Expired Proof (iat too old)", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{
					Method: validMethod,
					URI:    validURI,
					MutateClaims: func(c *claims) {
						c.IAT = time.Now().Add(-10 * time.Minute).Unix()
					},
				})
				req.Header.Add("DPoP", proof)
				return req
			}, "", "invalid iat claim"),
			Entry("Future Proof (iat in future)", func() *http.Request {
				req := httptest.NewRequest(validMethod, validURI, nil)
				proof := generateTestDpop(testDpopOpts{
					Method: validMethod,
					URI:    validURI,
					MutateClaims: func(c *claims) {
						c.IAT = time.Now().Add(10 * time.Minute).Unix()
					},
				})
				req.Header.Add("DPoP", proof)
				return req
			}, "", "invalid iat claim"),
		)

		It("rejection of replayed jti", func() {
			store := NewMemoryDpopStore()
			validator := NewDpopValidator(options.DefaultDpopTimeWindow, store)

			token := "token"
			req1 := httptest.NewRequest(validMethod, validURI, nil)
			proof := generateTestDpop(testDpopOpts{Method: validMethod, URI: validURI, AccessToken: token})
			req1.Header.Add("DPoP", proof)

			_, err := validator.ValidateDPopToken(req1, token)
			Expect(err).ToNot(HaveOccurred())

			// Replay same request
			req2 := httptest.NewRequest(validMethod, validURI, nil)
			req2.Header.Add("DPoP", proof)

			_, err = validator.ValidateDPopToken(req2, token)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("jti has already been used (replay attack)"))
		})
	})
})

func RunStoreTests(getStore func() DpopStore, advance func(time.Duration)) {
	var store DpopStore
	var ctx context.Context

	BeforeEach(func() {
		store = getStore()
		ctx = context.Background()
	})

	It("returns true for first time seeing a JTI", func() {
		seen, err := store.MarkJtiSeen(ctx, "jkt", "test-jti-1", time.Now().Add(1*time.Minute))
		Expect(err).ToNot(HaveOccurred())
		Expect(seen).To(BeTrue())
	})

	It("returns false for second time seeing a JTI", func() {
		jti := "test-jti-2"
		_, _ = store.MarkJtiSeen(ctx, "jkt", jti, time.Now().Add(1*time.Minute))
		seen, err := store.MarkJtiSeen(ctx, "jkt", jti, time.Now().Add(1*time.Minute))
		Expect(err).ToNot(HaveOccurred())
		Expect(seen).To(BeFalse())
	})

	It("returns true after JTI has expired", func() {
		jti := "test-jti-expire"
		_, err := store.MarkJtiSeen(ctx, "jkt", jti, time.Now().Add(50*time.Millisecond))
		Expect(err).ToNot(HaveOccurred())

		if advance != nil {
			advance(100 * time.Millisecond)
		} else {
			time.Sleep(100 * time.Millisecond)
		}

		seen, err := store.MarkJtiSeen(ctx, "jkt", jti, time.Now().Add(1*time.Minute))
		Expect(err).ToNot(HaveOccurred())
		Expect(seen).To(BeTrue())
	})

	It("handles multiple distinct JTIs", func() {
		seen1, err1 := store.MarkJtiSeen(ctx, "jkt", "jti-a", time.Now().Add(1*time.Minute))
		seen2, err2 := store.MarkJtiSeen(ctx, "jkt", "jti-b", time.Now().Add(1*time.Minute))
		Expect(err1).ToNot(HaveOccurred())
		Expect(err2).ToNot(HaveOccurred())
		Expect(seen1).To(BeTrue())
		Expect(seen2).To(BeTrue())
	})
}
