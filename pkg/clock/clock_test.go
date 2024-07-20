package clock_test

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/clock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	testGlobalEpoch = 1000000000
	testLocalEpoch  = 1234567890
)

var _ = Describe("Clock suite", func() {
	var testClock = clock.Clock{}

	AfterEach(func() {
		clock.Reset()
		testClock.Reset()
	})

	Context("Global time not overridden", func() {
		It("errors when trying to Add", func() {
			err := clock.Add(123 * time.Hour)
			Expect(err).To(HaveOccurred())
		})

		Context("Clock not mocked via Set", func() {
			const (
				outsideTolerance = int32(0)
				withinTolerance  = int32(1)
			)

			It("uses time.After for After", func() {
				var tolerance int32
				go func() {
					time.Sleep(10 * time.Millisecond)
					atomic.StoreInt32(&tolerance, withinTolerance)
				}()
				go func() {
					time.Sleep(30 * time.Millisecond)
					atomic.StoreInt32(&tolerance, outsideTolerance)
				}()

				Expect(atomic.LoadInt32(&tolerance)).To(Equal(outsideTolerance))

				<-testClock.After(20 * time.Millisecond)
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(withinTolerance))

				<-testClock.After(20 * time.Millisecond)
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(outsideTolerance))
			})

			It("uses time.AfterFunc for AfterFunc", func() {
				var tolerance int32
				go func() {
					time.Sleep(10 * time.Millisecond)
					atomic.StoreInt32(&tolerance, withinTolerance)
				}()
				go func() {
					time.Sleep(30 * time.Millisecond)
					atomic.StoreInt32(&tolerance, outsideTolerance)
				}()

				Expect(atomic.LoadInt32(&tolerance)).To(Equal(outsideTolerance))

				var wg sync.WaitGroup
				wg.Add(1)
				testClock.AfterFunc(20*time.Millisecond, func() {
					wg.Done()
				})
				wg.Wait()
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(withinTolerance))

				wg.Add(1)
				testClock.AfterFunc(20*time.Millisecond, func() {
					wg.Done()
				})
				wg.Wait()
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(outsideTolerance))
			})

			It("uses time.Now for Now", func() {
				a := time.Now()
				b := testClock.Now()
				Expect(b.Sub(a).Round(10 * time.Millisecond)).To(Equal(0 * time.Millisecond))
			})

			It("uses time.Since for Since", func() {
				past := time.Now().Add(-60 * time.Second)
				Expect(time.Since(past).Round(10 * time.Millisecond)).
					To(Equal(60 * time.Second))
			})

			It("uses time.Sleep for Sleep", func() {
				var tolerance int32
				go func() {
					time.Sleep(10 * time.Millisecond)
					atomic.StoreInt32(&tolerance, withinTolerance)
				}()
				go func() {
					time.Sleep(30 * time.Millisecond)
					atomic.StoreInt32(&tolerance, outsideTolerance)
				}()

				Expect(atomic.LoadInt32(&tolerance)).To(Equal(outsideTolerance))

				testClock.Sleep(20 * time.Millisecond)
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(withinTolerance))

				testClock.Sleep(20 * time.Millisecond)
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(outsideTolerance))
			})

			It("uses time.Tick for Tick", func() {
				var tolerance int32
				go func() {
					time.Sleep(10 * time.Millisecond)
					atomic.StoreInt32(&tolerance, withinTolerance)
				}()
				go func() {
					time.Sleep(50 * time.Millisecond)
					atomic.StoreInt32(&tolerance, outsideTolerance)
				}()

				ch := testClock.Tick(20 * time.Millisecond)
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(outsideTolerance))
				<-ch
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(withinTolerance))
				<-ch
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(withinTolerance))
				<-ch
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(outsideTolerance))
			})

			It("uses time.Ticker for Ticker", func() {
				var tolerance int32
				go func() {
					time.Sleep(10 * time.Millisecond)
					atomic.StoreInt32(&tolerance, withinTolerance)
				}()
				go func() {
					time.Sleep(50 * time.Millisecond)
					atomic.StoreInt32(&tolerance, outsideTolerance)
				}()

				ticker := testClock.Ticker(20 * time.Millisecond)
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(outsideTolerance))
				<-ticker.C
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(withinTolerance))
				<-ticker.C
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(withinTolerance))
				<-ticker.C
				Expect(atomic.LoadInt32(&tolerance)).To(Equal(outsideTolerance))
			})

			It("errors if Add is used", func() {
				err := testClock.Add(100 * time.Second)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("Clock mocked via Set", func() {
			var now = time.Unix(testLocalEpoch, 0)

			BeforeEach(func() {
				testClock.Set(now)
			})

			It("mocks After", func() {
				var after int32
				ready := make(chan struct{})
				ch := testClock.After(10 * time.Second)
				go func(ch <-chan time.Time) {
					close(ready)
					<-ch
					atomic.StoreInt32(&after, 1)
				}(ch)
				<-ready

				err := testClock.Add(9 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&after)).To(Equal(int32(0)))

				err = testClock.Add(1 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&after)).To(Equal(int32(1)))
			})

			It("mocks AfterFunc", func() {
				var after int32
				testClock.AfterFunc(10*time.Second, func() {
					atomic.StoreInt32(&after, 1)
				})

				err := testClock.Add(9 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&after)).To(Equal(int32(0)))

				err = testClock.Add(1 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&after)).To(Equal(int32(1)))
			})

			It("mocks AfterFunc with a stopped timer", func() {
				var after int32
				timer := testClock.AfterFunc(10*time.Second, func() {
					atomic.StoreInt32(&after, 1)
				})
				timer.Stop()

				err := testClock.Add(11 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&after)).To(Equal(int32(0)))
			})

			It("mocks Now", func() {
				Expect(testClock.Now()).To(Equal(now))
				err := testClock.Add(123 * time.Hour)
				Expect(err).ToNot(HaveOccurred())
				Expect(testClock.Now()).To(Equal(now.Add(123 * time.Hour)))
			})

			It("mocks Since", func() {
				Expect(testClock.Since(time.Unix(testLocalEpoch-100, 0))).
					To(Equal(100 * time.Second))
			})

			It("mocks Sleep", func() {
				var after int32
				ready := make(chan struct{})
				go func() {
					close(ready)
					testClock.Sleep(10 * time.Second)
					atomic.StoreInt32(&after, 1)
				}()
				<-ready

				err := testClock.Add(9 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&after)).To(Equal(int32(0)))

				err = testClock.Add(1 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&after)).To(Equal(int32(1)))
			})

			It("mocks Tick", func() {
				var ticks int32
				ready := make(chan struct{})
				go func() {
					close(ready)
					tick := testClock.Tick(10 * time.Second)
					for ticks < 5 {
						<-tick
						atomic.AddInt32(&ticks, 1)
					}
				}()
				<-ready

				Expect(atomic.LoadInt32(&ticks)).To(Equal(int32(0)))

				err := testClock.Add(9 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&ticks)).To(Equal(int32(0)))

				err = testClock.Add(1 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&ticks)).To(Equal(int32(1)))

				err = testClock.Add(30 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&ticks)).To(Equal(int32(4)))

				err = testClock.Add(10 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&ticks)).To(Equal(int32(5)))
			})

			It("mocks Ticker", func() {
				var ticks int32
				ready := make(chan struct{})
				go func() {
					ticker := testClock.Ticker(10 * time.Second)
					close(ready)
					for ticks < 5 {
						<-ticker.C
						atomic.AddInt32(&ticks, 1)
					}
				}()
				<-ready

				Expect(atomic.LoadInt32(&ticks)).To(Equal(int32(0)))

				err := testClock.Add(9 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&ticks)).To(Equal(int32(0)))

				err = testClock.Add(1 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&ticks)).To(Equal(int32(1)))

				err = testClock.Add(30 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&ticks)).To(Equal(int32(4)))

				err = testClock.Add(10 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&ticks)).To(Equal(int32(5)))
			})

			It("mocks Timer", func() {
				var after int32
				ready := make(chan struct{})
				go func() {
					timer := testClock.Timer(10 * time.Second)
					close(ready)
					<-timer.C
					atomic.AddInt32(&after, 1)
				}()
				<-ready

				err := testClock.Add(9 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&after)).To(Equal(int32(0)))

				err = testClock.Add(1 * time.Second)
				Expect(err).ToNot(HaveOccurred())
				Expect(atomic.LoadInt32(&after)).To(Equal(int32(1)))
			})
		})
	})

	Context("Global time overridden", func() {
		var (
			globalNow = time.Unix(testGlobalEpoch, 0)
			localNow  = time.Unix(testLocalEpoch, 0)
		)

		BeforeEach(func() {
			clock.Set(globalNow)
		})

		Context("Clock not mocked via Set", func() {
			It("uses globally mocked Now", func() {
				Expect(testClock.Now()).To(Equal(globalNow))
				err := clock.Add(123 * time.Hour)
				Expect(err).ToNot(HaveOccurred())
				Expect(testClock.Now()).To(Equal(globalNow.Add(123 * time.Hour)))
			})

			It("errors when Add is called on the local Clock", func() {
				err := testClock.Add(100 * time.Hour)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("Clock is mocked via Set", func() {
			BeforeEach(func() {
				testClock.Set(localNow)
			})

			It("uses the local mock and ignores the global", func() {
				Expect(testClock.Now()).To(Equal(localNow))

				err := clock.Add(456 * time.Hour)
				Expect(err).ToNot(HaveOccurred())

				err = testClock.Add(123 * time.Hour)
				Expect(err).ToNot(HaveOccurred())

				Expect(testClock.Now()).To(Equal(localNow.Add(123 * time.Hour)))
			})
		})
	})
})
