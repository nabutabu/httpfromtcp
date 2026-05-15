package tls13

import (
	"bytes"
	"testing"

	"httpFromTcp/internal/tls13/handshake"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshakeRoundtrip(t *testing.T) {
	tests := []struct {
		name    string
		msgType byte
		data    []byte
	}{
		{
			name:    "client hello with data",
			msgType: byte(1),
			data:    []byte{0x01, 0x02, 0x03},
		},
		{
			name:    "server hello with text",
			msgType: byte(2),
			data:    []byte("hello tls 1.3"),
		},
		{
			name:    "certificate with binary payload",
			msgType: byte(11),
			data:    []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
		},
		{
			name:    "finished with single byte",
			msgType: byte(20),
			data:    []byte{0x00},
		},
		{
			name:    "encrypted extensions with empty data",
			msgType: byte(8),
			data:    []byte(nil),
		},
		{
			name:    "new session ticket with mixed data",
			msgType: byte(4),
			data:    []byte("session-ticket-data"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)

			err := writeHandshake(buf, tt.msgType, tt.data)
			require.NoError(t, err)

			hs, err := readHandshake(buf)
			require.NoError(t, err)
			assert.Equal(t, handshake.HandshakeComplete, hs.HandshakeState)
		})
	}
}

func TestHandshakeRoundtripLargePayload(t *testing.T) {
	payload := make([]byte, 1<<14)
	for i := range payload {
		payload[i] = byte(i)
	}

	buf := new(bytes.Buffer)

	err := writeHandshake(buf, byte(11), payload)
	require.NoError(t, err)

	hs, err := readHandshake(buf)
	require.NoError(t, err)
	assert.Equal(t, handshake.HandshakeComplete, hs.HandshakeState)
}

func TestHandshakeReadInvalidType(t *testing.T) {
	buf := new(bytes.Buffer)
	buf.Write([]byte{0xFF, 0x00, 0x01, 0x00})
	_, err := readHandshake(buf)
	require.Error(t, err)
}

func TestHandshakeReadTruncated(t *testing.T) {
	buf := new(bytes.Buffer)
	buf.Write([]byte{0x01, 0x00, 0x05, 0x01, 0x02})
	_, err := readHandshake(buf)
	require.Error(t, err)
}
