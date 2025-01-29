package combohelper

import (
	"fmt"

	"github.com/aixoio/aixoio-privacy-tools/lib/aes"
	"github.com/aixoio/aixoio-privacy-tools/lib/asconhelper"
	"github.com/aixoio/aixoio-privacy-tools/lib/xchachahelper"
)

func AesXChaCha20Poly1305Ascon128aEncrypt(key, data []byte) ([]byte, error) {
	const keySize = 640 / 8
	if len(key) != keySize {
		return nil, fmt.Errorf("key length must be 640 bits")
	}

	aesKey := key[:32]
	xChaChaKey := key[32:64]
	asconKey := key[64:]

	data, err := asconhelper.Ascon128aEncrypt(asconKey, data)
	if err != nil {
		return nil, err
	}

	data, err = xchachahelper.XChaCha20Poly1305Encrypt(xChaChaKey, data)
	if err != nil {
		return nil, err
	}

	data, err = aes.AesGCMEncrypt(aesKey, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func AesXChaCha20Poly1305Ascon128aDecrypt(key, data []byte) ([]byte, error) {
	const keySize = 640 / 8
	if len(key) != keySize {
		return nil, fmt.Errorf("key length must be 640 bits")
	}

	aesKey := key[:32]
	xChaChaKey := key[32:64]
	asconKey := key[64:]

	data, err := aes.AesGCMDecrypt(aesKey, data)
	if err != nil {
		return nil, err
	}

	data, err = xchachahelper.XChaCha20Poly1305Decrypt(xChaChaKey, data)
	if err != nil {
		return nil, err
	}

	data, err = asconhelper.Ascon128aDecrypt(asconKey, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
