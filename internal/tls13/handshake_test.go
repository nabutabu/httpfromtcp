package tls13

import (
	"testing"

	"httpFromTcp/internal/tls13/client_hello"

	"github.com/stretchr/testify/assert"
)

func TestNewServerHello(t *testing.T) {
	random := [32]byte{}
	for i := range random {
		random[i] = byte(i)
	}
	sessionID := []byte{0x01, 0x02, 0x03}
	cipherSuite := uint16(0x1301)
	keyShare := client_hello.KeyShareEntry{
		Group: 0x001D,
		KeyExchange: []byte{
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		},
	}

	result := NewServerHello(random, sessionID, cipherSuite, keyShare)

	assert.Equal(t, byte(0x03), result[0])
	assert.Equal(t, byte(0x03), result[1])

	for i := 0; i < 32; i++ {
		assert.Equal(t, byte(i), result[2+i])
	}

	assert.Equal(t, byte(3), result[34])
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, result[35:38])

	assert.Equal(t, byte(0x13), result[38])
	assert.Equal(t, byte(0x01), result[39])

	assert.Equal(t, byte(0x00), result[40])

	extLen := int(result[41])<<8 | int(result[42])
	assert.Equal(t, len(result)-43, extLen)

	extData := result[43:]
	offset := 0

	assert.Equal(t, byte(0x00), extData[offset])
	assert.Equal(t, byte(0x2b), extData[offset+1])
	svDataLen := int(extData[offset+2])<<8 | int(extData[offset+3])
	assert.Equal(t, 2, svDataLen)
	assert.Equal(t, byte(0x03), extData[offset+4])
	assert.Equal(t, byte(0x04), extData[offset+5])
	offset += 4 + svDataLen

	assert.Equal(t, byte(0x00), extData[offset])
	assert.Equal(t, byte(0x33), extData[offset+1])
	ksDataLen := int(extData[offset+2])<<8 | int(extData[offset+3])
	assert.Equal(t, 4+len(keyShare.KeyExchange), ksDataLen)
	assert.Equal(t, byte(0x00), extData[offset+4])
	assert.Equal(t, byte(0x1D), extData[offset+5])
	ksKeyLen := int(extData[offset+6])<<8 | int(extData[offset+7])
	assert.Equal(t, len(keyShare.KeyExchange), ksKeyLen)
	assert.Equal(t, keyShare.KeyExchange, extData[offset+8:offset+8+ksKeyLen])
}

func TestNewServerHelloEmptySessionID(t *testing.T) {
	random := [32]byte{}
	cipherSuite := uint16(0x1302)
	keyShare := client_hello.KeyShareEntry{
		Group:       0x0017,
		KeyExchange: []byte{0xaa, 0xbb},
	}

	result := NewServerHello(random, []byte{}, cipherSuite, keyShare)

	assert.Equal(t, byte(0x00), result[34])
	assert.Equal(t, byte(0x13), result[35])
	assert.Equal(t, byte(0x02), result[36])
}
