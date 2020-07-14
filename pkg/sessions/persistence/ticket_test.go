package persistence

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	. "github.com/onsi/gomega"
)

// TestLegacyV5DecodeSession tests the fallback to LegacyV5DecodeSession
// when a V5 encoded session is in Redis
//
// TODO: Remove when this is deprecated (likely V7)
func Test_legacyV5LoadSession(t *testing.T) {
	testCases, _, _ := sessions.CreateLegacyV5TestCases(t)

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			g := NewWithT(t)

			secret := make([]byte, aes.BlockSize)
			_, err := io.ReadFull(rand.Reader, secret)
			g.Expect(err).ToNot(HaveOccurred())
			ticket := &Ticket{
				Secret: secret,
				Options: &options.Cookie{
					Secret: base64.RawURLEncoding.EncodeToString([]byte(sessions.LegacyV5TestSecret)),
				},
			}

			encrypted, err := legacyStoreValue(tc.Input, ticket.Secret)
			g.Expect(err).ToNot(HaveOccurred())

			ss, err := ticket.legacyV5LoadSession(encrypted)
			if tc.Error {
				g.Expect(err).To(HaveOccurred())
				g.Expect(ss).To(BeNil())
				return
			}
			g.Expect(err).ToNot(HaveOccurred())

			// Compare sessions without *time.Time fields
			exp := *tc.Output
			exp.CreatedAt = nil
			exp.ExpiresOn = nil
			act := *ss
			act.CreatedAt = nil
			act.ExpiresOn = nil
			g.Expect(exp).To(Equal(act))
		})
	}
}

// legacyStoreValue implements the legacy V5 Redis persistence AES-CFB value encryption
//
// TODO: Remove when this is deprecated (likely V7)
func legacyStoreValue(value string, ticketSecret []byte) ([]byte, error) {
	ciphertext := make([]byte, len(value))
	block, err := aes.NewCipher(ticketSecret)
	if err != nil {
		return nil, fmt.Errorf("error initiating cipher block: %v", err)
	}

	// Use secret as the Initialization Vector too, because each entry has it's own key
	stream := cipher.NewCFBEncrypter(block, ticketSecret)
	stream.XORKeyStream(ciphertext, []byte(value))

	return ciphertext, nil
}
