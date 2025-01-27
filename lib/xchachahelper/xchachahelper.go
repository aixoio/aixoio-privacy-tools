package xchachahelper

import (
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

func XChaCha20Poly1305Encrypt(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	cipherText := aead.Seal(nonce, nonce, data, nil)

	return cipherText, nil
}

func XChaCha20Poly1305Decrypt(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	nonce, cipherbytes := data[:nonceSize], data[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, cipherbytes, nil)
	if err != nil {
		return nil, err

	}

	return plaintext, err
}
