package tls13

import (
	"encoding/binary"
	"errors"
	"httpFromTcp/internal/tls13/handshake"
	"io"
)

/**
* Read Handshake
* HandshakeType (1) | Length (3) | Message (variable)
 */
func readHandshake(r io.Reader) (*handshake.Handshake, error) {
	buf := make([]byte, 8)
	hs := handshake.Handshake{State: handshake.HandshakeInitialized}
	var line string
	var bytesRead int
	var bytesParsed int

	for {
		if hs.State == handshake.HandshakeComplete {
			return &hs, nil
		}

		// if there is a request in flight read more bytes
		n, err := r.Read(buf)
		if err != nil {
			return nil, errors.New("Error reading data")
		}

		line += string(buf[:n])
		bytesRead += n

		// received some amount of text
		bytes, err := hs.Parse([]byte(line))
		if err != nil {
			return nil, err
		}

		// after parsing set line to the remainder of parts
		bytesParsed += bytes
		line = line[bytes:]
	}
}

func writeHandshake(w io.Writer, msgType byte, data []byte) error {
	var res []byte

	res = append(res, msgType)

	size := make([]byte, 2)
	binary.BigEndian.PutUint16(size, uint16(len(data)))
	res = append(res, size...)

	res = append(res, data...)

	_, err := w.Write(res)
	return err
}
