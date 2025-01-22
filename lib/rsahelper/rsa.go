package rsahelper

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash"
	"io"

	"github.com/aixoio/aixoio-privacy-tools/lib/hashing"
)

func ExportPubkeyAsPEMStr(pubkey *rsa.PublicKey) (string, error) {
	if pubkey == nil {
		return "", errors.New("public key is nil")
	}
	pubKeyBytes := x509.MarshalPKCS1PublicKey(pubkey)
	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return string(pubKeyPem), nil
}

func ExportPrivKeyAsPEMStr(privkey *rsa.PrivateKey) (string, error) {
	if privkey == nil {
		return "", errors.New("private key is nil")
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
	privKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return string(privKeyPem), nil
}

func ExportPEMStrToPrivKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func ExportPEMStrToPubKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func EncryptOAEP(hash hash.Hash, random io.Reader, public *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := public.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, random, public, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	return encryptedBytes, nil
}

func DecryptOAEP(hash hash.Hash, random io.Reader, private *rsa.PrivateKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := private.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, random, private, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}

func RsaEncrypt(pub *rsa.PublicKey, dat []byte) ([]byte, error) {
	cipherText, err := EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub,
		dat,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func RsaDecrypt(pri *rsa.PrivateKey, dat []byte) ([]byte, error) {
	text, err := DecryptOAEP(
		sha256.New(),
		rand.Reader,
		pri,
		dat,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return text, nil
}

func RsaSign(pri *rsa.PrivateKey, dat []byte) ([]byte, error) {
	hashed := hashing.Sha256_to_bytes(dat)
	sig, err := rsa.SignPSS(rand.Reader, pri, crypto.SHA256, hashed, nil)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func RsaVerify(pub *rsa.PublicKey, sig []byte, dat []byte) bool {
	err := rsa.VerifyPSS(pub, crypto.SHA256, hashing.Sha256_to_bytes(dat), sig, nil)
	return err == nil
}
