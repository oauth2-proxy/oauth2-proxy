package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"hash"
)

type APISignature interface {
	GetSignature(signedDate string) string
}

type apiSignature struct {
	secretKey string
	sharedKey string
	hash      hash.Hash
}

func NewAPISignature(secretKey, sharedKey string) APISignature {
	secret := fmt.Sprintf("DHPWS%s", secretKey)
	return &apiSignature{secretKey: secretKey, sharedKey: sharedKey, hash: hmac.New(sha256.New, []byte(secret))}
}

func (s *apiSignature) GetSignature(signedDate string) string {
	s.hash.Write([]byte(b64.StdEncoding.EncodeToString([]byte(signedDate))))
	b := s.hash.Sum(nil)
	sEnc := b64.StdEncoding.EncodeToString(b)
	s.hash.Reset()
	return fmt.Sprintf("HmacSHA256;Credential:%s;SignedHeaders:SignedDate;Signature:%s", s.sharedKey, sEnc)
}
