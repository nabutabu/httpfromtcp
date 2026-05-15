package tls13

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// RFC 5869 Appendix A.1 - Test Case 1: SHA-256 basic extract
func TestHkdfExtract_RFC5869_TestCase1(t *testing.T) {
	ikm := []byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	expected := mustDecodeHex(t, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

	prk := hkdfExtract(salt, ikm, sha256.New)
	assert.Equal(t, expected, prk)
}

// RFC 5869 Appendix A.2 - Test Case 2: SHA-256 with longer inputs
func TestHkdfExtract_RFC5869_TestCase2(t *testing.T) {
	ikm := make([]byte, 80)
	for i := range ikm {
		ikm[i] = byte(i)
	}
	salt := make([]byte, 80)
	for i := range salt {
		salt[i] = byte(i + 0x60)
	}
	expected := mustDecodeHex(t, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")

	prk := hkdfExtract(salt, ikm, sha256.New)
	assert.Equal(t, expected, prk)
}

// RFC 5869 Appendix A.3 - Test Case 3: SHA-256 with zero-length salt
func TestHkdfExtract_RFC5869_TestCase3(t *testing.T) {
	ikm := []byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
	expected := mustDecodeHex(t, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")

	prk := hkdfExtract([]byte{}, ikm, sha256.New)
	assert.Equal(t, expected, prk)
}

// RFC 8448 Section 3: derive secret for handshake "tls13 derived"
func TestHkdfExpandLabel_Derived(t *testing.T) {
	secret := mustDecodeHex(t, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
	context := mustDecodeHex(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	expected := mustDecodeHex(t, "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")

	out := hkdfExpandLabel(secret, "derived", context, 32, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: derive secret "tls13 c hs traffic"
func TestHkdfExpandLabel_CHsTraffic(t *testing.T) {
	secret := mustDecodeHex(t, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
	context := mustDecodeHex(t, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
	expected := mustDecodeHex(t, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")

	out := hkdfExpandLabel(secret, "c hs traffic", context, 32, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: derive secret "tls13 s hs traffic"
func TestHkdfExpandLabel_SHsTraffic(t *testing.T) {
	secret := mustDecodeHex(t, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
	context := mustDecodeHex(t, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
	expected := mustDecodeHex(t, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")

	out := hkdfExpandLabel(secret, "s hs traffic", context, 32, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: derive secret for master "tls13 derived"
func TestHkdfExpandLabel_DerivedMaster(t *testing.T) {
	secret := mustDecodeHex(t, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
	context := mustDecodeHex(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	expected := mustDecodeHex(t, "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4")

	out := hkdfExpandLabel(secret, "derived", context, 32, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: derive server write traffic key for handshake data
func TestHkdfExpandLabel_Key(t *testing.T) {
	secret := mustDecodeHex(t, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	expected := mustDecodeHex(t, "3fce516009c21727d0f2e4e86ee403bc")

	out := hkdfExpandLabel(secret, "key", nil, 16, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: derive server write traffic IV for handshake data
func TestHkdfExpandLabel_IV(t *testing.T) {
	secret := mustDecodeHex(t, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	expected := mustDecodeHex(t, "5d313eb2671276ee13000b30")

	out := hkdfExpandLabel(secret, "iv", nil, 12, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: server finished key "tls13 finished"
func TestHkdfExpandLabel_Finished(t *testing.T) {
	secret := mustDecodeHex(t, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	expected := mustDecodeHex(t, "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8")

	out := hkdfExpandLabel(secret, "finished", nil, 32, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: client finished key "tls13 finished"
func TestHkdfExpandLabel_FinishedClient(t *testing.T) {
	secret := mustDecodeHex(t, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
	expected := mustDecodeHex(t, "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4")

	out := hkdfExpandLabel(secret, "finished", nil, 32, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: derive secret "tls13 c ap traffic"
func TestHkdfExpandLabel_CApTraffic(t *testing.T) {
	secret := mustDecodeHex(t, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
	context := mustDecodeHex(t, "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
	expected := mustDecodeHex(t, "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")

	out := hkdfExpandLabel(secret, "c ap traffic", context, 32, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: derive secret "tls13 s ap traffic"
func TestHkdfExpandLabel_SApTraffic(t *testing.T) {
	secret := mustDecodeHex(t, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
	context := mustDecodeHex(t, "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
	expected := mustDecodeHex(t, "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")

	out := hkdfExpandLabel(secret, "s ap traffic", context, 32, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: derive secret "tls13 exp master"
func TestHkdfExpandLabel_ExpMaster(t *testing.T) {
	secret := mustDecodeHex(t, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
	context := mustDecodeHex(t, "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
	expected := mustDecodeHex(t, "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50")

	out := hkdfExpandLabel(secret, "exp master", context, 32, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 4 (0-RTT): derive secret "tls13 c e traffic"
func TestHkdfExpandLabel_CETraffic(t *testing.T) {
	secret := mustDecodeHex(t, "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c")
	context := mustDecodeHex(t, "08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913")
	expected := mustDecodeHex(t, "3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62")

	out := hkdfExpandLabel(secret, "c e traffic", context, 32, sha256.New)
	assert.Equal(t, expected, out)
}

// RFC 8448 Section 3: derive resumption secret "tls13 resumption"
func TestHkdfExpandLabel_Resumption(t *testing.T) {
	secret := mustDecodeHex(t, "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c")
	context := []byte{0x00, 0x00}
	expected := mustDecodeHex(t, "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3")

	out := hkdfExpandLabel(secret, "resumption", context, 32, sha256.New)
	assert.Equal(t, expected, out)
}
