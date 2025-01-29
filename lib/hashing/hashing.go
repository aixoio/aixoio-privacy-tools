package hashing

import (
	"crypto/sha256"

	"golang.org/x/crypto/sha3"
)

func Sha256_to_bytes(dat []byte) []byte {
	hash_32 := sha256.Sum256([]byte(dat))
	hash := hash_32[:]
	return hash
}

func Sha3_512_to_bytes(dat []byte) []byte {
	hash_64 := sha3.Sum512([]byte(dat))
	hash := hash_64[:]
	return hash
}

func SHAKE256_768_to_bytes(dat []byte) ([]byte, error) {
	h := sha3.NewShake256()
	h.Write(dat)
	out := make([]byte, 96) // 768 bits = 96 bytes
	if _, err := h.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func SHAKE256_640_to_bytes(dat []byte) ([]byte, error) {
	h := sha3.NewShake256()
	h.Write(dat)
	out := make([]byte, 80) // 640 bits = 80 bytes
	if _, err := h.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func Sha256_to_bytes_128bit(dat []byte) []byte {
	hash_32 := sha256.Sum256([]byte(dat))
	hash := hash_32[:16] // Truncate to 128 bits (16 bytes)
	return hash
}

func Sha256_to_bytes_160bit(dat []byte) []byte {
	hash_32 := sha256.Sum256([]byte(dat))
	hash := hash_32[:20] // Truncate to 160 bits (20 bytes)
	return hash
}
