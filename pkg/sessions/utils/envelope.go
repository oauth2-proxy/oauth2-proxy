package utils

import (
	"github.com/vmihailenco/msgpack/v4"
)

type SessionEnvelope struct {
	Type       int    `msgpack:"t"`
	Compressed bool   `msgpack:"c,omitempty"`
	Encryption int    `msgpack:"e,omitempty"`
	Data       []byte `msgpack:"d"`
}

func (s *SessionEnvelope) Marshal() ([]byte, error) {
	return msgpack.Marshal(s)
}

func UnmarshalSessionEnvelope(packed []byte) (*SessionEnvelope, error) {
	var se SessionEnvelope
	var err error

	err = msgpack.Unmarshal(packed, &se)
	if err != nil {
		return nil, err
	}
	return &se, nil
}
