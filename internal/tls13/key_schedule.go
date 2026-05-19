package tls13

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

type HkdfLabel struct {
	size    uint16 // 2 bytes big-endian: the desired output length
	label   byte   // 1-byte length prefix, then "tls13 " + label_string
	context byte   // 1-byte length prefix, then the context bytes
}

type KeySet struct {
	ClientHandshakeTrafficSecret   []byte
	ServerHandshakeTrafficSecret   []byte
	ClientApplicationTrafficSecret []byte
	ServerApplicationTrafficSecret []byte
	ServerHandshakeKeys            CipherKeys
	ServerApplicationKeys          CipherKeys
	ClientHandshakeKeys            CipherKeys
	ClientApplicationKeys          CipherKeys
	ResumptionMasterSecret         []byte
}

type CipherKeys struct {
	Key []byte // 16 bytes for AES-128
	Iv  []byte // 12 bytes
}

func DeriveEarlySecret(psk []byte) []byte {
	return hkdfExtract(nil, psk, sha256.New)
}

func DeriveHandshakeSecret(earlySecret, sharedSecret []byte) []byte {
	salt := deriveSecret(earlySecret, "derived", sha256.New)
	return hkdfExtract(salt, sharedSecret, sha256.New)
}

func DeriveMasterSecret(handshakeSecret []byte) []byte {
	salt := deriveSecret(handshakeSecret, "derived", sha256.New)
	return hkdfExtract(salt, nil, sha256.New)
}

func deriveSecret(secret []byte, label string, hash func() hash.Hash) []byte {
	emptyHash := hash().Sum(nil)
	return hkdfExpandLabel(secret, label, emptyHash, hash().Size(), hash)
}

func DeriveTrafficKeys(secret []byte) CipherKeys {
	return CipherKeys{
		Key: hkdfExpandLabel(secret, "key", []byte{}, 16, sha256.New),
		Iv:  hkdfExpandLabel(secret, "iv", []byte{}, 12, sha256.New),
	}
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
