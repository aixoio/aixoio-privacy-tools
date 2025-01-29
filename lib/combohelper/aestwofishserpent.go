package combohelper

import (
	"fmt"

	"github.com/aixoio/aixoio-privacy-tools/lib/aes"
	"github.com/aixoio/aixoio-privacy-tools/lib/serpent"
	"github.com/aixoio/aixoio-privacy-tools/lib/twofish"
)

func AesTwofishSerpentEncrypt(key, data []byte) ([]byte, error) {
	const keyLength = 768 / 8
	if len(key) != keyLength {
		return nil, fmt.Errorf("key length must be 768 bits")
	}

	serpentKey := key[:32]
	twofishKey := key[32:64]
	aesKey := key[64:]

	data, err := serpent.SerpentHMACEncrypt(serpentKey, data)
	if err != nil {
		return nil, err
	}

	data, err = twofish.TwofishHMACEncrypt(twofishKey, data)
	if err != nil {
		return nil, err
	}

	data, err = aes.AesGCMEncrypt(aesKey, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func AesTwofishSerpentDecrypt(key, data []byte) ([]byte, error) {
	const keyLength = 768 / 8
	if len(key) != keyLength {
		return nil, fmt.Errorf("key length must be 768 bits")
	}

	serpentKey := key[:32]
	twofishKey := key[32:64]
	aesKey := key[64:]

	data, err := aes.AesGCMDecrypt(aesKey, data)
	if err != nil {
		return nil, err
	}

	data, err = twofish.TwofishHMACDecrypt(twofishKey, data)
	if err != nil {
		return nil, err
	}

	data, err = serpent.SerpentHMACDecrypt(serpentKey, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
