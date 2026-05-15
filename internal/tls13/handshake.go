package tls13

import (
	"encoding/binary"
	"errors"
	"httpFromTcp/internal/tls13/client_hello"
	"httpFromTcp/internal/tls13/handshake"
	"io"
)

func readClientHello(r io.Reader) (*client_hello.ClientHello, error) {
	buf := make([]byte, 8)
	clientHello := client_hello.ClientHello{}
	var line string
	var bytesRead int
	var bytesParsed int

	for {
		if clientHello.ClientHelloState == int(client_hello.ClientHelloCompleted) {
			return &clientHello, nil
		}

		// if there is a request in flight read more bytes
		n, err := r.Read(buf)
		if err != nil {
			return nil, errors.New("Error reading data")
		}

		line += string(buf[:n])
		bytesRead += n

		// received some amount of text
		bytes, err := clientHello.Parse([]byte(line))
		if err != nil {
			return nil, err
		}

		// after parsing set line to the remainder of parts
		bytesParsed += bytes
		line = line[bytes:]
	}
}

/**
* Read Handshake
* HandshakeType (1) | Length (3) | Message (variable)
 */
func readHandshake(r io.Reader) (*handshake.Handshake, error) {
	buf := make([]byte, 8)
	hs := handshake.Handshake{HandshakeState: handshake.HandshakeInitialized}
	var line string
	var bytesRead int
	var bytesParsed int

	for {
		if hs.HandshakeState == handshake.HandshakeComplete {
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
