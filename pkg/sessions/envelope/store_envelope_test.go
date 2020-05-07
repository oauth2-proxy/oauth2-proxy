package envelope

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshalAndUnmarshalStoreEnvelop(t *testing.T) {
	se := &StoreEnvelope{
		Type:       CookieType,
		Compressed: false,
		Encryption: NoEncryption,
		Data:       []byte("My enveloped data as byte slice"),
	}

	encoded, err := se.Marshal()
	assert.Equal(t, nil, err)

	decoded, err := UnmarshalStoreEnvelope(encoded)
	assert.Equal(t, nil, err)

	assert.Equal(t, decoded.Type, CookieType)
	assert.Equal(t, decoded.Compressed, false)
	assert.Equal(t, decoded.Encryption, NoEncryption)
	assert.Equal(t, decoded.Data, se.Data)
}

// Any legacy JSON sessions will throw an error (easy way to fallback to legacy)
func TestUnmarshalStoreEnvelopBadData(t *testing.T) {
	legacy := "email:user@domain.com user:just-user|I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==|xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==|123456789|qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K"
	_, err := UnmarshalStoreEnvelope([]byte(legacy))
	assert.Error(t, err)
}
