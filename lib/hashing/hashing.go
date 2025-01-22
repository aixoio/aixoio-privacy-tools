package hashing

import "crypto/sha256"

func Sha256_to_bytes(dat []byte) []byte {
	hash_32 := sha256.Sum256([]byte(dat))
	hash := hash_32[:]
	return hash
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
