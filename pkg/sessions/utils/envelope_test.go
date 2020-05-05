package utils

import (
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/utils/envelope"
	"github.com/stretchr/testify/assert"
)

func TestMarshalAndUnmarshalSessionEnvelop(t *testing.T) {
	se := &SessionEnvelope{
		Type:       envelope.CookieType,
		Compressed: false,
		Encryption: envelope.NoEncryption,
		Data:       []byte("My enveloped data as byte slice"),
	}

	encoded, err := se.Marshal()
	assert.Equal(t, nil, err)

	decoded, err := UnmarshalSessionEnvelope(encoded)
	assert.Equal(t, nil, err)

	assert.Equal(t, decoded.Type, envelope.CookieType)
	assert.Equal(t, decoded.Compressed, false)
	assert.Equal(t, decoded.Encryption, envelope.NoEncryption)
	assert.Equal(t, decoded.Data, se.Data)
}

// Any legacy JSON sessions will throw an error (easy way to fallback to legacy)
func TestUnmarshalSessionEnvelopBadData(t *testing.T) {
	legacy := "email:user@domain.com user:just-user|I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==|xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==|123456789|qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K"
	_, err := UnmarshalSessionEnvelope([]byte(legacy))
	assert.Error(t, err)
}
