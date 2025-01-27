package twofish

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/aixoio/aixoio-privacy-tools/lib/padding"
	"golang.org/x/crypto/twofish"
)

func TwofishHMACEncrypt(key, data []byte) ([]byte, error) {
	padded_text, err := padding.PKCS5Padding(data, twofish.BlockSize)
	if err != nil {
		return nil, err
	}

	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher_text := make([]byte, twofish.BlockSize+len(padded_text))

	iv := cipher_text[:twofish.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipher_text[twofish.BlockSize:], padded_text)

	h := hmac.New(sha256.New, key)
	h.Write(cipher_text)
	hmacValue := h.Sum(nil)

	cipher_text = append(cipher_text, hmacValue...)

	return cipher_text, err
}

func TwofishHMACDecrypt(key, data []byte) ([]byte, error) {
	hmacSize := sha256.Size
	if len(data) < twofish.BlockSize+hmacSize {
		return nil, errors.New("data too short to contain IV and HMAC")
	}

	ciphertextWithIV := data[:len(data)-hmacSize]
	receivedHmac := data[len(data)-hmacSize:]

	h := hmac.New(sha256.New, key)
	h.Write(ciphertextWithIV)
	expectedHmac := h.Sum(nil)

	if !hmac.Equal(receivedHmac, expectedHmac) {
		return nil, errors.New("HMAC verification failed")
	}

	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ciphertextWithIV[:twofish.BlockSize]
	cipher_text := ciphertextWithIV[twofish.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(cipher_text, cipher_text)

	decrypted, err := padding.PKCS5Trimming(cipher_text)
	if err != nil {
		return nil, err
	}

	return decrypted, err
}
