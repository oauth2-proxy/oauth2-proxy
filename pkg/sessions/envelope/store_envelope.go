package envelope

import (
	"github.com/vmihailenco/msgpack/v4"
)

// StoreEnvelope wraps cookies that various session stores use
// This allows easy detection of improper session formats as configurations change
type StoreEnvelope struct {
	Type       int    `msgpack:"t"`
	Compressed bool   `msgpack:"c,omitempty"`
	Encryption int    `msgpack:"e,omitempty"`
	Data       []byte `msgpack:"d"`
}

// Marshal the StoreEnvelope to MessagePack
func (s *StoreEnvelope) Marshal() ([]byte, error) {
	return msgpack.Marshal(s)
}

// Unmarshal a StoreEnvelope from MessagePack encoded bytes
func UnmarshalStoreEnvelope(packed []byte) (*StoreEnvelope, error) {
	var se StoreEnvelope

	err := msgpack.Unmarshal(packed, &se)
	if err != nil {
		return nil, err
	}
	return &se, nil
}
