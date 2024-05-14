package rsahelper

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"hash"
	"io"

	"github.com/aixoio/aixoio-privacy-tools/lib/hashing"
)

func ExportPubkeyAsPEMStr(pubkey *rsa.PublicKey) string {
	pubKeyPem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubkey),
	}))
	return pubKeyPem
}

func ExportPrivKeyAsPEMStr(privkey *rsa.PrivateKey) string {
	priKeyPem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	}))
	return priKeyPem
}

func ExportPEMStrToPrivKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

func ExportPEMStrToPubKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

func Generate_rsa_pey_kair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	return privateKey, &privateKey.PublicKey
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

func Rsa_enc(pub *rsa.PublicKey, dat []byte) []byte {
	cipherText, err := EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub,
		dat,
		nil,
	)
	if err != nil {
		panic(err)
	}
	return cipherText
}

func Rsa_dec(pri *rsa.PrivateKey, dat []byte) []byte {
	text, err := DecryptOAEP(
		sha256.New(),
		rand.Reader,
		pri,
		dat,
		nil,
	)
	if err != nil {
		panic(err)
	}
	return text
}

func Rsa_Sign(pri *rsa.PrivateKey, dat []byte) []byte {
	hashed := hashing.Sha256_to_bytes(dat)
	sig, err := rsa.SignPSS(rand.Reader, pri, crypto.SHA256, hashed, nil)
	if err != nil {
		panic(err)
	}
	return sig
}

// Returns true if success
func Rsa_Verify(pub *rsa.PublicKey, sig []byte, dat []byte) bool {
	err := rsa.VerifyPSS(pub, crypto.SHA256, hashing.Sha256_to_bytes(dat), sig, nil)
	return err == nil
}
