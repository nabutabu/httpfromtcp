package tls13

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

func Encrypt(keys CipherKeys, seqNum uint64, contentType byte, plaintext []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(keys.Key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], seqNum)
	for i := 0; i < 12; i++ {
		nonce[i] ^= keys.Iv[i]
	}

	innerPlaintext := make([]byte, len(plaintext)+1)
	copy(innerPlaintext, plaintext)
	innerPlaintext[len(plaintext)] = contentType

	length := len(innerPlaintext) + aesgcm.Overhead()
	aad := make([]byte, 5)
	aad[0] = byte(ApplicationData)
	aad[1] = 0x03
	aad[2] = 0x03
	binary.BigEndian.PutUint16(aad[3:], uint16(length))

	return aesgcm.Seal(nil, nonce, innerPlaintext, aad), nil
}

func Decrypt(keys CipherKeys, seqNum uint64, ciphertext []byte) (contentType byte, plaintext []byte, err error) {
	block, err := aes.NewCipher(keys.Key)
	if err != nil {
		return 0, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, nil, err
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], seqNum)
	for i := 0; i < 12; i++ {
		nonce[i] ^= keys.Iv[i]
	}

	aad := make([]byte, 5)
	aad[0] = byte(ApplicationData)
	aad[1] = 0x03
	aad[2] = 0x03
	binary.BigEndian.PutUint16(aad[3:], uint16(len(ciphertext)))

	innerPlaintext, err := aesgcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return 0, nil, err
	}

	for i := len(innerPlaintext) - 1; i >= 0; i-- {
		if innerPlaintext[i] != 0 {
			return innerPlaintext[i], innerPlaintext[:i], nil
		}
	}

	return 0, nil, errors.New("Corrupt record")
}
