package tls13

import (
	"crypto/hkdf"
	"crypto/hmac"
	"hash"
)

type HkdfLabel struct {
	size    uint16 // 2 bytes big-endian: the desired output length
	label   byte   // 1-byte length prefix, then "tls13 " + label_string
	context byte   // 1-byte length prefix, then the context bytes
}

func hkdfExtract(salt, ikm []byte, hash func() hash.Hash) []byte {
	if salt == nil {
		salt = make([]byte, hash().Size())
	}

	mac := hmac.New(hash, salt) // salt is the key
	mac.Write(ikm)              // ikm is the message

	return mac.Sum(nil)
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int, hash func() hash.Hash) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 2+1+len(fullLabel)+1+len(context))
	info[0] = byte(length >> 8)
	info[1] = byte(length)
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	info[3+len(fullLabel)] = byte(len(context))
	copy(info[4+len(fullLabel):], context)

	out, err := hkdf.Expand(hash, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}
