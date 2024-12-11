package persistence

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Session Ticket Tests", func() {
	Context("encodeTicket & decodeTicket", func() {
		type ticketTableInput struct {
			ticket        *ticket
			encodedTicket string
			expectedError error
		}

		DescribeTable("encodeTicket should decodeTicket back when valid",
			func(in ticketTableInput) {
				if in.ticket != nil {
					enc := in.ticket.encodeTicket()
					Expect(enc).To(Equal(in.encodedTicket))

					dec, err := decodeTicket(enc, in.ticket.options)
					Expect(err).ToNot(HaveOccurred())
					Expect(dec).To(Equal(in.ticket))
				} else {
					_, err := decodeTicket(in.encodedTicket, nil)
					Expect(err).To(MatchError(in.expectedError))
				}
			},
			Entry("with a valid ticket", ticketTableInput{
				ticket: &ticket{
					id:     "dummy-0123456789abcdef",
					secret: []byte("0123456789abcdef"),
					options: &options.Cookie{
						Name: "dummy",
					},
				},
				encodedTicket: fmt.Sprintf("v2.%s.%s",
					base64.RawURLEncoding.EncodeToString([]byte("dummy-0123456789abcdef")),
					base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))),
				expectedError: nil,
			}),
			Entry("with an invalid encoded ticket with 1 part", ticketTableInput{
				ticket:        nil,
				encodedTicket: "dummy-0123456789abcdef",
				expectedError: errors.New("failed to decode ticket"),
			}),
			Entry("with an invalid base64 encoded secret", ticketTableInput{
				ticket:        nil,
				encodedTicket: "dummy-0123456789abcdef.@)#($*@)#(*$@)#(*$",
				expectedError: fmt.Errorf("failed to decode ticket: failed to decode encryption secret: illegal base64 data at input byte 0"),
			}),
		)
	})

	Context("saveSession", func() {
		It("uses the passed save function", func() {
			t, err := newTicket(&options.Cookie{Name: "dummy"})
			Expect(err).ToNot(HaveOccurred())

			c, err := t.makeCipher()
			Expect(err).ToNot(HaveOccurred())

			ss := &sessions.SessionState{User: "foobar"}
			store := map[string][]byte{}
			err = t.saveSession(ss, func(k string, v []byte, e time.Duration) error {
				store[k] = v
				return nil
			})
			Expect(err).ToNot(HaveOccurred())

			stored, err := sessions.DecodeSessionState(store[t.id], c, false)
			Expect(err).ToNot(HaveOccurred())
			Expect(stored).To(Equal(ss))
		})

		It("errors when the saveFunc errors", func() {
			t, err := newTicket(&options.Cookie{Name: "dummy"})
			Expect(err).ToNot(HaveOccurred())

			err = t.saveSession(
				&sessions.SessionState{User: "foobar"},
				func(k string, v []byte, e time.Duration) error {
					return errors.New("save error")
				})
			Expect(err).To(MatchError(errors.New("save error")))
		})
	})

	Context("loadSession", func() {
		It("uses the passed load function", func() {
			t, err := newTicket(&options.Cookie{Name: "dummy"})
			Expect(err).ToNot(HaveOccurred())

			c, err := t.makeCipher()
			Expect(err).ToNot(HaveOccurred())

			ss := &sessions.SessionState{
				User: "foobar",
				Lock: &sessions.NoOpLock{},
			}
			loadedSession, err := t.loadSession(
				func(k string) ([]byte, error) {
					return ss.EncodeSessionState(c, false)
				},
				func(k string) sessions.Lock {
					return &sessions.NoOpLock{}
				})
			Expect(err).ToNot(HaveOccurred())
			Expect(loadedSession).To(Equal(ss))
		})

		It("errors when the loadFunc errors", func() {
			t, err := newTicket(&options.Cookie{Name: "dummy"})
			Expect(err).ToNot(HaveOccurred())

			data, err := t.loadSession(
				func(k string) ([]byte, error) {
					return nil, errors.New("load error")
				},
				func(k string) sessions.Lock {
					return &sessions.NoOpLock{}
				})
			Expect(data).To(BeNil())
			Expect(err).To(MatchError(errors.New("failed to load the session state with the ticket: load error")))
		})
	})

	Context("clearSession", func() {
		It("uses the passed clear function", func() {
			t, err := newTicket(&options.Cookie{Name: "dummy"})
			Expect(err).ToNot(HaveOccurred())

			var tracker string
			err = t.clearSession(func(k string) error {
				tracker = k
				return nil
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(tracker).To(Equal(t.id))
		})

		It("errors when the clearFunc errors", func() {
			t, err := newTicket(&options.Cookie{Name: "dummy"})
			Expect(err).ToNot(HaveOccurred())

			err = t.clearSession(func(k string) error {
				return errors.New("clear error")
			})
			Expect(err).To(MatchError(errors.New("clear error")))
		})
	})
})
