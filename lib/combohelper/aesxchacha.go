package combohelper

import (
	"fmt"

	"github.com/aixoio/aixoio-privacy-tools/lib/aes"
	"github.com/aixoio/aixoio-privacy-tools/lib/xchachahelper"
)

func AesxChaCha20Poly1305Encrypt(key, data []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, fmt.Errorf("key length must be 512 bits")
	}

	aesKey := key[:32]
	xChaChaKey := key[32:]

	data, err := xchachahelper.XChaCha20Poly1305Encrypt(xChaChaKey, data)
	if err != nil {
		return nil, err
	}

	data, err = aes.AesGCMEncrypt(aesKey, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func AesxChaCha20Poly1305Decrypt(key, data []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, fmt.Errorf("key length must be 512 bits")
	}

	aesKey := key[:32]
	xChaChaKey := key[32:]

	data, err := aes.AesGCMDecrypt(aesKey, data)
	if err != nil {
		return nil, err
	}

	data, err = xchachahelper.XChaCha20Poly1305Decrypt(xChaChaKey, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
