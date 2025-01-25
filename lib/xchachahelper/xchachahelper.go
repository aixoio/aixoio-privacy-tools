package xchachahelper

import "golang.org/x/crypto/chacha20poly1305"

func XChaCha20Poly1305Encrypt(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())

	cipherText := aead.Seal(nil, nonce, data, nil)

	return cipherText, nil
}

func XChaCha20Poly1305Decrypt(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())

	plaintext, err := aead.Open(nil, nonce, data, nil)

	return plaintext, err
}
