package client_hello

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildClientHelloWithKeyShares(t *testing.T) []byte {
	t.Helper()
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, uint16(0x0303))

	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	buf.Write(random)

	buf.WriteByte(0x00)

	cipherSuites := []uint16{0x1301, 0x1302}
	binary.Write(buf, binary.BigEndian, uint16(len(cipherSuites)*2))
	for _, cs := range cipherSuites {
		binary.Write(buf, binary.BigEndian, cs)
	}

	buf.WriteByte(0x01)
	buf.WriteByte(0x00)

	extBuf := new(bytes.Buffer)

	binary.Write(extBuf, binary.BigEndian, uint16(43))
	binary.Write(extBuf, binary.BigEndian, uint16(2))
	binary.Write(extBuf, binary.BigEndian, uint16(0x0304))

	binary.Write(extBuf, binary.BigEndian, uint16(51))

	ksData := new(bytes.Buffer)

	binary.Write(ksData, binary.BigEndian, uint16(0x001D))
	x25519Key := make([]byte, 32)
	for i := range x25519Key {
		x25519Key[i] = byte(i + 0x10)
	}
	binary.Write(ksData, binary.BigEndian, uint16(len(x25519Key)))
	ksData.Write(x25519Key)

	binary.Write(ksData, binary.BigEndian, uint16(0x0017))
	p256Key := make([]byte, 65)
	for i := range p256Key {
		p256Key[i] = byte(i + 0x40)
	}
	binary.Write(ksData, binary.BigEndian, uint16(len(p256Key)))
	ksData.Write(p256Key)

	binary.Write(extBuf, binary.BigEndian, uint16(ksData.Len()))
	extBuf.Write(ksData.Bytes())

	binary.Write(buf, binary.BigEndian, uint16(extBuf.Len()))
	buf.Write(extBuf.Bytes())

	return buf.Bytes()
}

func TestParseClientHelloWithMultipleKeyShares(t *testing.T) {
	raw := buildClientHelloWithKeyShares(t)

	var ch ClientHello
	_, err := ch.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, ClientHelloCompleted, State(ch.ClientHelloState))

	assert.Equal(t, [2]byte{0x03, 0x03}, ch.LegacyVersion)

	expectedRandom := [32]byte{}
	for i := range expectedRandom {
		expectedRandom[i] = byte(i)
	}
	assert.Equal(t, expectedRandom, ch.Random)

	assert.Empty(t, ch.LegacySessionID)

	assert.Equal(t, []uint16{0x1301, 0x1302}, ch.CipherSuites)
	assert.Equal(t, []byte{0x00}, ch.LegacyCompression)

	require.Len(t, ch.Extensions, 2)
	assert.Equal(t, ExtensionType(43), ch.Extensions[0].Type)
	assert.Equal(t, []byte{0x03, 0x04}, ch.Extensions[0].Data)
	assert.Equal(t, ExtensionType(51), ch.Extensions[1].Type)

	require.Len(t, ch.KeyShare, 2)
	assert.Equal(t, uint16(0x001D), ch.KeyShare[0].Group)
	assert.Equal(t, uint16(0x0017), ch.KeyShare[1].Group)

	expectedX25519 := make([]byte, 32)
	for i := range expectedX25519 {
		expectedX25519[i] = byte(i + 0x10)
	}
	assert.Equal(t, expectedX25519, ch.KeyShare[0].KeyExchange)

	expectedP256 := make([]byte, 65)
	for i := range expectedP256 {
		expectedP256[i] = byte(i + 0x40)
	}
	assert.Equal(t, expectedP256, ch.KeyShare[1].KeyExchange)
}
