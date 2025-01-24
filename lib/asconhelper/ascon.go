package asconhelper

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/cipher/ascon"
)

func AsconEncrypt(key, plaintext []byte) ([]byte, error) {
	var mode ascon.Mode

	switch len(key) {
	case ascon.Ascon128.KeySize():
		mode = ascon.Ascon128
	case ascon.Ascon80pq.KeySize():
		mode = ascon.Ascon80pq
	default:
		return nil, fmt.Errorf("ascon: invalid key length %d, must be 16 or 20 bytes", len(key))
	}

	cipher, err := ascon.New(key, mode)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := cipher.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func AsconDecrypt(key, ciphertext []byte) ([]byte, error) {
	var mode ascon.Mode

	switch len(key) {
	case ascon.Ascon128.KeySize():
		mode = ascon.Ascon128
	case ascon.Ascon80pq.KeySize():
		mode = ascon.Ascon80pq
	default:
		return nil, errors.New("invalid key length")
	}

	cipher, err := ascon.New(key, mode)
	if err != nil {
		return nil, err
	}

	nonceSize := cipher.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]
	return cipher.Open(nil, nonce, actualCiphertext, nil)
}
func Ascon128aEncrypt(key, plaintext []byte) ([]byte, error) {
	var mode ascon.Mode

	switch len(key) {
	case ascon.Ascon128a.KeySize():
		mode = ascon.Ascon128a
	default:
		return nil, fmt.Errorf("ascon: invalid key length %d, must be 16", len(key))
	}

	cipher, err := ascon.New(key, mode)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := cipher.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func Ascon128aDecrypt(key, ciphertext []byte) ([]byte, error) {
	var mode ascon.Mode

	switch len(key) {
	case ascon.Ascon128a.KeySize():
		mode = ascon.Ascon128a
	default:
		return nil, errors.New("invalid key length")
	}

	cipher, err := ascon.New(key, mode)
	if err != nil {
		return nil, err
	}

	nonceSize := cipher.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]
	return cipher.Open(nil, nonce, actualCiphertext, nil)
}
