package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Cipher provides methods to encrypt and decrypt
type Cipher interface {
	Encrypt(value []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type base64Cipher struct {
	Cipher Cipher
}

// NewBase64Cipher returns a new AES Cipher for encrypting cookie values
// and wrapping them in Base64 -- Supports Legacy encryption scheme
func NewBase64Cipher(c Cipher) Cipher {
	return &base64Cipher{Cipher: c}
}

// Encrypt encrypts a value with the embedded Cipher & Base64 encodes it
func (c *base64Cipher) Encrypt(value []byte) ([]byte, error) {
	encrypted, err := c.Cipher.Encrypt(value)
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(encrypted)), nil
}

// Decrypt Base64 decodes a value & decrypts it with the embedded Cipher
func (c *base64Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode value %s", err)
	}

	return c.Cipher.Decrypt(encrypted)
}

type cfbCipher struct {
	cipher.Block
}

// NewCFBCipher returns a new AES CFB Cipher
func NewCFBCipher(secret []byte) (Cipher, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	return &cfbCipher{Block: c}, err
}

// Encrypt with AES CFB
func (c *cfbCipher) Encrypt(value []byte) ([]byte, error) {
	ciphertext := make([]byte, aes.BlockSize+len(value))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to create initialization vector %s", err)
	}

	stream := cipher.NewCFBEncrypter(c.Block, iv) //nolint:staticcheck
	stream.XORKeyStream(ciphertext[aes.BlockSize:], value)
	return ciphertext, nil
}

// Decrypt an AES CFB ciphertext
func (c *cfbCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted value should be at least %d bytes, but is only %d bytes", aes.BlockSize, len(ciphertext))
	}

	iv, ciphertext := ciphertext[:aes.BlockSize], ciphertext[aes.BlockSize:]
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(c.Block, iv) //nolint:staticcheck
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

type gcmCipher struct {
	cipher.Block
}

// NewGCMCipher returns a new AES GCM Cipher
func NewGCMCipher(secret []byte) (Cipher, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	return &gcmCipher{Block: c}, err
}

// Encrypt with AES GCM on raw bytes
func (c *gcmCipher) Encrypt(value []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(c.Block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Using nonce as Seal's dst argument results in it being the first
	// chunk of bytes in the ciphertext. Decrypt retrieves the nonce/IV from this.
	ciphertext := gcm.Seal(nonce, nonce, value, nil)
	return ciphertext, nil
}

// Decrypt an AES GCM ciphertext
func (c *gcmCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(c.Block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
