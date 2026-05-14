package tls13

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordRoundtrip(t *testing.T) {
	tests := []struct {
		name        string
		contentType ContentType
		data        []byte
	}{
		{
			name:        "handshake with data",
			contentType: ContentTypeHandshake,
			data:        []byte{0x01, 0x02, 0x03},
		},
		{
			name:        "application data with text",
			contentType: ApplicationData,
			data:        []byte("hello tls 1.3"),
		},
		{
			name:        "alert with single byte",
			contentType: Alert,
			data:        []byte{0x00},
		},
		{
			name:        "handshake with empty data",
			contentType: ContentTypeHandshake,
			data:        []byte(nil),
		},
		{
			name:        "application data with binary payload",
			contentType: ApplicationData,
			data:        []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)

			err := writeRecord(buf, tt.contentType, tt.data)
			require.NoError(t, err)

			contentType, data, err := readRecord(buf)
			require.NoError(t, err)
			assert.Equal(t, tt.contentType, contentType)
			assert.Equal(t, tt.data, data)
		})
	}
}

func TestRecordRoundtripLargePayload(t *testing.T) {
	payload := make([]byte, 1<<14)
	for i := range payload {
		payload[i] = byte(i)
	}

	buf := new(bytes.Buffer)

	err := writeRecord(buf, ApplicationData, payload)
	require.NoError(t, err)

	contentType, data, err := readRecord(buf)
	require.NoError(t, err)
	assert.Equal(t, ApplicationData, contentType)
	assert.Equal(t, payload, data)
}
