package tls13

import (
	"encoding/binary"
	"errors"
	"httpFromTcp/internal/tls13/client_hello"
	"httpFromTcp/internal/tls13/handshake"
	"io"
)

type ServerHello struct {
    LegacyVersion     [2]byte  // always 0x0303
    Random            [32]byte
    LegacySessionID   []byte   // echo client's session ID
    CipherSuite       [2]byte  // 0x1301 for TLS_AES_128_GCM_SHA256
    LegacyCompression byte     // 0x00
    Extensions        []client_hello.Extension
}

func NewServerHello(random [32]byte, sessionID []byte, cipherSuite uint16, keyShare client_hello.KeyShareEntry) []byte {
	var buf []byte

	buf = append(buf, 0x03, 0x03)

	buf = append(buf, random[:]...)

	buf = append(buf, byte(len(sessionID)))
	buf = append(buf, sessionID...)

	cs := make([]byte, 2)
	binary.BigEndian.PutUint16(cs, cipherSuite)
	buf = append(buf, cs...)

	buf = append(buf, 0x00)

	var exts []byte

	sv := make([]byte, 4)
	binary.BigEndian.PutUint16(sv[0:2], 43)
	binary.BigEndian.PutUint16(sv[2:4], 2)
	exts = append(exts, sv...)
	exts = append(exts, 0x03, 0x04)

	ksHeader := make([]byte, 4)
	binary.BigEndian.PutUint16(ksHeader[0:2], 51)
	binary.BigEndian.PutUint16(ksHeader[2:4], uint16(4+len(keyShare.KeyExchange)))
	exts = append(exts, ksHeader...)
	group := make([]byte, 2)
	binary.BigEndian.PutUint16(group, keyShare.Group)
	exts = append(exts, group...)
	keyLen := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLen, uint16(len(keyShare.KeyExchange)))
	exts = append(exts, keyLen...)
	exts = append(exts, keyShare.KeyExchange...)

	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(exts)))
	buf = append(buf, extLen...)
	buf = append(buf, exts...)

	return buf
}

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
