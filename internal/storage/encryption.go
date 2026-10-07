package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}

	sealed := aead.Seal(nil, nonce, plaintext, nil)

	tagSize := 16
	ciphertext := sealed[:len(sealed)-tagSize]
	authTag := sealed[len(sealed)-tagSize:]

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    authTag,
		Ciphertext: ciphertext,
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce length")
	}

	if len(payload.AuthTag) != 16 {
		return nil, fmt.Errorf("invalid authentication tag length")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	sealed := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	sealed = append(sealed, payload.Ciphertext...)
	sealed = append(sealed, payload.AuthTag...)

	plaintext, err := aead.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt encrypted payload: %w", err)
	}

	return plaintext, nil
}