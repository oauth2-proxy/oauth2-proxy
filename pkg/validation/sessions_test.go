package validation

import (
	"time"

	"github.com/Bose/minisentinel"
	"github.com/alicebob/miniredis/v2"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sessions", func() {
	const (
		idTokenConflictMsg     = "id_token claim for header \"X-ID-Token\" requires oauth tokens in sessions. session_cookie_minimal cannot be set"
		accessTokenConflictMsg = "access_token claim for header \"X-Access-Token\" requires oauth tokens in sessions. session_cookie_minimal cannot be set"
		cookieRefreshMsg       = "cookie_refresh > 0 requires oauth tokens in sessions. session_cookie_minimal cannot be set"
	)

	type cookieMinimalTableInput struct {
		opts       *options.Options
		errStrings []string
	}

	DescribeTable("validateSessionCookieMinimal",
		func(o *cookieMinimalTableInput) {
			Expect(validateSessionCookieMinimal(o.opts)).To(ConsistOf(o.errStrings))
		},
		Entry("No minimal cookie session", &cookieMinimalTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: false,
					},
				},
			},
			errStrings: []string{},
		}),
		Entry("No minimal cookie session & request header has access_token claim", &cookieMinimalTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: false,
					},
				},
				InjectRequestHeaders: []options.Header{
					{
						Name: "X-Access-Token",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "access_token",
								},
							},
						},
					},
				},
			},
			errStrings: []string{},
		}),
		Entry("Minimal cookie session no conflicts", &cookieMinimalTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
			},
			errStrings: []string{},
		}),
		Entry("Request Header id_token conflict", &cookieMinimalTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
				InjectRequestHeaders: []options.Header{
					{
						Name: "X-ID-Token",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "id_token",
								},
							},
						},
					},
				},
			},
			errStrings: []string{idTokenConflictMsg},
		}),
		Entry("Response Header id_token conflict", &cookieMinimalTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
				InjectResponseHeaders: []options.Header{
					{
						Name: "X-ID-Token",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "id_token",
								},
							},
						},
					},
				},
			},
			errStrings: []string{idTokenConflictMsg},
		}),
		Entry("Request Header access_token conflict", &cookieMinimalTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
				InjectRequestHeaders: []options.Header{
					{
						Name: "X-Access-Token",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "access_token",
								},
							},
						},
					},
				},
			},
			errStrings: []string{accessTokenConflictMsg},
		}),
		Entry("CookieRefresh conflict", &cookieMinimalTableInput{
			opts: &options.Options{
				Cookie: options.Cookie{
					Refresh: time.Hour,
				},
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
			},
			errStrings: []string{cookieRefreshMsg},
		}),
		Entry("Multiple conflicts", &cookieMinimalTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Cookie: options.CookieStoreOptions{
						Minimal: true,
					},
				},
				InjectResponseHeaders: []options.Header{
					{
						Name: "X-ID-Token",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "id_token",
								},
							},
						},
					},
				},
				InjectRequestHeaders: []options.Header{
					{
						Name: "X-Access-Token",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "access_token",
								},
							},
						},
					},
				},
			},
			errStrings: []string{idTokenConflictMsg, accessTokenConflictMsg},
		}),
	)

	const (
		clusterAndSentinelMsg     = "unable to initialize a redis client: options redis-use-sentinel and redis-use-cluster are mutually exclusive"
		parseWrongSchemeMsg       = "unable to initialize a redis client: unable to parse redis url: redis: invalid URL scheme: https"
		parseWrongFormatMsg       = "unable to initialize a redis client: unable to parse redis url: redis: invalid database number: \"wrong\""
		invalidPasswordSetMsg     = "unable to set a redis initialization key: WRONGPASS invalid username-password pair"
		invalidPasswordDelMsg     = "unable to delete the redis initialization key: WRONGPASS invalid username-password pair"
		unreachableRedisSetMsg    = "unable to set a redis initialization key: dial tcp 127.0.0.1:65535: connect: connection refused"
		unreachableRedisDelMsg    = "unable to delete the redis initialization key: dial tcp 127.0.0.1:65535: connect: connection refused"
		unreachableSentinelSetMsg = "unable to set a redis initialization key: redis: all sentinels specified in configuration are unreachable"
		unrechableSentinelDelMsg  = "unable to delete the redis initialization key: redis: all sentinels specified in configuration are unreachable"
	)

	type redisStoreTableInput struct {
		// miniredis setup details
		password        string
		useSentinel     bool
		setAddr         bool
		setSentinelAddr bool
		setMasterName   bool

		opts       *options.Options
		errStrings []string
	}

	DescribeTable("validateRedisSessionStore",
		func(o *redisStoreTableInput) {
			mr, err := miniredis.Run()
			Expect(err).ToNot(HaveOccurred())
			mr.RequireAuth(o.password)
			defer mr.Close()

			if o.setAddr && !o.useSentinel {
				o.opts.Session.Redis.ConnectionURL = "redis://" + mr.Addr()
			}

			if o.useSentinel {
				ms := minisentinel.NewSentinel(mr)
				Expect(ms.Start()).To(Succeed())
				defer ms.Close()

				if o.setSentinelAddr {
					o.opts.Session.Redis.SentinelConnectionURLs = []string{"redis://" + ms.Addr()}
				}
				if o.setMasterName {
					o.opts.Session.Redis.SentinelMasterName = ms.MasterInfo().Name
				}
			}

			Expect(validateRedisSessionStore(o.opts)).To(ConsistOf(o.errStrings))
		},
		Entry("cookie sessions are skipped", &redisStoreTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.CookieSessionStoreType,
				},
			},
			errStrings: []string{},
		}),
		Entry("connect successfully to pure redis", &redisStoreTableInput{
			setAddr: true,

			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
				},
			},
			errStrings: []string{},
		}),
		Entry("failed redis connection with wrong address", &redisStoreTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						ConnectionURL: "redis://127.0.0.1:65535",
					},
				},
			},
			errStrings: []string{unreachableRedisSetMsg, unreachableRedisDelMsg},
		}),
		Entry("fail to parse an invalid connection URL with wrong scheme", &redisStoreTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						ConnectionURL: "https://example.com",
					},
				},
			},
			errStrings: []string{parseWrongSchemeMsg},
		}),
		Entry("fail to parse an invalid connection URL with invalid format", &redisStoreTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						ConnectionURL: "redis://127.0.0.1:6379/wrong",
					},
				},
			},
			errStrings: []string{parseWrongFormatMsg},
		}),
		Entry("connect successfully to pure redis with password", &redisStoreTableInput{
			password: "abcdef123",
			setAddr:  true,

			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						Password: "abcdef123",
					},
				},
			},
			errStrings: []string{},
		}),
		Entry("failed connection with wrong password", &redisStoreTableInput{
			password: "abcdef123",
			setAddr:  true,

			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						Password: "zyxwtuv987",
					},
				},
			},
			errStrings: []string{invalidPasswordSetMsg, invalidPasswordDelMsg},
		}),
		Entry("connect successfully to sentinel redis", &redisStoreTableInput{
			useSentinel:     true,
			setSentinelAddr: true,
			setMasterName:   true,

			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						UseSentinel: true,
					},
				},
			},
			errStrings: []string{},
		}),
		Entry("connect successfully to sentinel redis with password", &redisStoreTableInput{
			password:        "abcdef123",
			useSentinel:     true,
			setSentinelAddr: true,
			setMasterName:   true,

			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						Password:    "abcdef123",
						UseSentinel: true,
					},
				},
			},
			errStrings: []string{},
		}),
		Entry("failed connection to sentinel redis with wrong password", &redisStoreTableInput{
			password:        "abcdef123",
			useSentinel:     true,
			setSentinelAddr: true,
			setMasterName:   true,

			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						Password:    "zyxwtuv987",
						UseSentinel: true,
					},
				},
			},
			errStrings: []string{invalidPasswordSetMsg, invalidPasswordDelMsg},
		}),
		Entry("failed connection to sentinel redis with wrong master name", &redisStoreTableInput{
			useSentinel:     true,
			setSentinelAddr: true,

			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						UseSentinel:        true,
						SentinelMasterName: "WRONG",
					},
				},
			},
			errStrings: []string{unreachableSentinelSetMsg, unrechableSentinelDelMsg},
		}),
		Entry("failed connection to sentinel redis with wrong address", &redisStoreTableInput{
			useSentinel:   true,
			setMasterName: true,

			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						UseSentinel:            true,
						SentinelConnectionURLs: []string{"redis://127.0.0.1:65535"},
					},
				},
			},
			errStrings: []string{unreachableSentinelSetMsg, unrechableSentinelDelMsg},
		}),
		Entry("sentinel and cluster both enabled fails", &redisStoreTableInput{
			opts: &options.Options{
				Session: options.SessionOptions{
					Type: options.RedisSessionStoreType,
					Redis: options.RedisStoreOptions{
						UseSentinel: true,
						UseCluster:  true,
					},
				},
			},
			errStrings: []string{clusterAndSentinelMsg},
		}),
	)
})
