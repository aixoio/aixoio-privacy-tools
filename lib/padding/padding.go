package padding

import (
	"bytes"
	"errors"
)

func PKCS5Padding(ciphertext []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("blockSize must be positive")
	}

	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...), nil
}

func PKCS5Trimming(encrypt []byte) ([]byte, error) {
	if len(encrypt) == 0 {
		return nil, errors.New("empty input")
	}

	padding := int(encrypt[len(encrypt)-1])
	if padding > len(encrypt) {
		return nil, errors.New("invalid padding")
	}

	return encrypt[:len(encrypt)-padding], nil
}
