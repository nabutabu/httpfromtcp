package tls13

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// RFC 4231 Test Case 2: HMAC-SHA256 with key="Jefe", data="what do ya want for nothing?"
func TestComputeVerifyData_RFC4231_TestCase2(t *testing.T) {
	key := []byte("Jefe")
	data := []byte("what do ya want for nothing?")
	expected := mustDecodeHex(t, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

	result := computeVerifyData(key, data)
	assert.Equal(t, expected, result)
}

// RFC 4231 Test Case 3: HMAC-SHA256 with 20-byte key of 0xaa and 50-byte data of 0xdd
func TestComputeVerifyData_RFC4231_TestCase3(t *testing.T) {
	key := make([]byte, 20)
	for i := range key {
		key[i] = 0xaa
	}
	data := make([]byte, 50)
	for i := range data {
		data[i] = 0xdd
	}
	expected := mustDecodeHex(t, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")

	result := computeVerifyData(key, data)
	assert.Equal(t, expected, result)
}

// RFC 4231 Test Case 4: HMAC-SHA256 with key=0x01..0x19, data=50 bytes 0xcd
func TestComputeVerifyData_RFC4231_TestCase4(t *testing.T) {
	key := make([]byte, 25)
	for i := range key {
		key[i] = byte(i + 1)
	}
	data := make([]byte, 50)
	for i := range data {
		data[i] = 0xcd
	}
	expected := mustDecodeHex(t, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")

	result := computeVerifyData(key, data)
	assert.Equal(t, expected, result)
}

// marshalFinished: verify the output format handshake type(0x14) | 2-byte length | verify_data
func TestMarshalFinished_Format(t *testing.T) {
	verifyData := mustDecodeHex(t, "b9027a0204b972b52cdefa58950fa1580d68c9cb124dbe691a7178f25c554b23")
	result := marshalFinished(verifyData)

	assert.Equal(t, byte(0x14), result[0])
	assert.Equal(t, byte(0x00), result[1])
	assert.Equal(t, byte(0x20), result[2])
	assert.Equal(t, verifyData, result[3:])
	assert.Len(t, result, 35)
}

func TestMarshalFinished_Empty(t *testing.T) {
	result := marshalFinished([]byte{})
	assert.Equal(t, []byte{0x14, 0x00, 0x00}, result)
}

func TestMarshalFinished_VariableSize(t *testing.T) {
	small := []byte{0x01, 0x02, 0x03}
	result := marshalFinished(small)
	assert.Equal(t, byte(0x14), result[0])
	assert.Equal(t, byte(0x00), result[1])
	assert.Equal(t, byte(0x03), result[2])
	assert.Equal(t, small, result[3:])
	assert.Len(t, result, 6)
}

// RFC 8448 Section 3 (Simple 1-RTT): Client Finished integration test.
// Handshake payloads extracted from draft-ietf-tls-tls13-vectors-06.
func TestRFC8448_ClientFinished_Integration(t *testing.T) {
	ch, _ := hex.DecodeString("010000c00303d4b9503c5e95c9eecc99ce6376ccad4dcc06d7c8f1fa44b0d95600e9a0586c67000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d0020b0f5019fb0f1e5376b8b1dfb905f1d915161bac37707dad8907bd71b9807b345002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001")
	sh, _ := hex.DecodeString("020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304")
	ee, _ := hex.DecodeString("080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000")
	cert, _ := hex.DecodeString("0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000")
	cv, _ := hex.DecodeString("0f00008408040080754040d0ddab8cf0e2da2bc4995b868ad745c8e1564e33cde17880a42392cc624aeef6b67bb3f0ae71d9d54a2309731d87dc59f642d733be2eb27484ad8a8c8eb3516a7ac57f2625e2b5c0888a8541f4e734f73d054761df1dd02f0e3e9a33cfa10b6e3eb4ebf7ac053b01fdabbddfc54133bcd24c8bbdceb223b2aa03452a29")
	serverFin, _ := hex.DecodeString("14000020ac86acbc9cd25a45b57ad5b64db15d4405cf8c80e314583ebf3283ef9a99310c")

	transcriptInput := append(append(append(append(append(ch, sh...), ee...), cert...), cv...), serverFin...)
	transcriptHash := sha256.Sum256(transcriptInput)

	expectedTranscriptHash := mustDecodeHex(t, "f8c19e8c77c03879bbc8eb6d56e00dd5d86ef55927eefc08e1b002b6ece05dbf")
	assert.Equal(t, expectedTranscriptHash, transcriptHash[:])

	clientFinKey := mustDecodeHex(t, "121bf58601b2ed13bf14b3eeacbd9da4baba1e143edb66a107795960fbd9e21f")
	verifyData := computeVerifyData(clientFinKey, transcriptHash[:])

	clientFin, _ := hex.DecodeString("14000020b9027a0204b972b52cdefa58950fa1580d68c9cb124dbe691a7178f25c554b23")
	assert.Equal(t, clientFin[4:], verifyData)

	marshaled := marshalFinished(verifyData)
	assert.Equal(t, byte(0x14), marshaled[0])
	assert.Equal(t, byte(0x00), marshaled[1])
	assert.Equal(t, byte(0x20), marshaled[2])
	assert.Equal(t, verifyData, marshaled[3:])
}

// RFC 8448 Section 3: Server Finished transcript hash
func TestRFC8448_ServerTranscriptHash(t *testing.T) {
	ch, _ := hex.DecodeString("010000c00303d4b9503c5e95c9eecc99ce6376ccad4dcc06d7c8f1fa44b0d95600e9a0586c67000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d0020b0f5019fb0f1e5376b8b1dfb905f1d915161bac37707dad8907bd71b9807b345002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001")
	sh, _ := hex.DecodeString("020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304")
	ee, _ := hex.DecodeString("080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000")
	cert, _ := hex.DecodeString("0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000")
	cv, _ := hex.DecodeString("0f00008408040080754040d0ddab8cf0e2da2bc4995b868ad745c8e1564e33cde17880a42392cc624aeef6b67bb3f0ae71d9d54a2309731d87dc59f642d733be2eb27484ad8a8c8eb3516a7ac57f2625e2b5c0888a8541f4e734f73d054761df1dd02f0e3e9a33cfa10b6e3eb4ebf7ac053b01fdabbddfc54133bcd24c8bbdceb223b2aa03452a29")

	transcriptInput := append(append(append(append(ch, sh...), ee...), cert...), cv...)
	transcriptHash := sha256.Sum256(transcriptInput)

	expected := mustDecodeHex(t, "4a208b0e9a26c61e4472817060d57cf4fd52b4010d0bfa18372e1747a7a6b2c7")
	assert.Equal(t, expected, transcriptHash[:])

	// computeVerifyData with server finished key produces correct verify_data
	serverFinKey := mustDecodeHex(t, "a80cb7d15db34a17abb0c23765be68c26d3f10da34905b099947e55e37db17b3")
	verifyData := computeVerifyData(serverFinKey, transcriptHash[:])
	expectedVerifyData := mustDecodeHex(t, "ac86acbc9cd25a45b57ad5b64db15d4405cf8c80e314583ebf3283ef9a99310c")
	assert.Equal(t, expectedVerifyData, verifyData)
}
