package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/aixoio/aixoio-privacy-tools/lib/padding"
)

func AesCBCEncrypt(key, data []byte) ([]byte, error) {
	padded_text := padding.PKCS5Padding(data, aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	cipher_text := make([]byte, aes.BlockSize+len(padded_text))

	iv := cipher_text[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipher_text[aes.BlockSize:], padded_text)

	return cipher_text, err
}

func AesCBCDecrypt(key, data []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	iv := data[:aes.BlockSize]
	cipher_text := data[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(cipher_text, cipher_text)

	decrypted := padding.PKCS5Trimming(cipher_text)

	return decrypted, err
}
