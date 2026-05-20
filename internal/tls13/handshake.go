package tls13

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"httpFromTcp/internal/tls13/client_hello"
	"httpFromTcp/internal/tls13/handshake"
	"io"
)

type ServerHello struct {
	LegacyVersion     [2]byte // always 0x0303
	Random            [32]byte
	LegacySessionID   []byte  // echo client's session ID
	CipherSuite       [2]byte // 0x1301 for TLS_AES_128_GCM_SHA256
	LegacyCompression byte    // 0x00
	Extensions        []client_hello.Extension
}

type SignatureScheme uint16

const (
	RSASSA_PSS_RSAE_SHA256 SignatureScheme = 0x0804
	ECDSA_SECP256R1_SHA256 SignatureScheme = 0x0403
)

func computeFinishedKey(trafficSecret []byte) []byte {
	//finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", hash.Size)
	
	return hkdfExpandLabel(trafficSecret, "finished", []byte(""), sha256.New().Size(), sha256.New)
}

func computeVerifyData(finishedKey []byte, transcriptHash []byte) []byte {
	mac := hmac.New(sha256.New, finishedKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil)
}

func marshalFinished(verifyData []byte) []byte {
	var buf []byte
	buf = append(buf, 0x14)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(verifyData)))
	buf = append(buf, length...)
	buf = append(buf, verifyData...)
	return buf
}

func signCertificateVerify(privKey crypto.PrivateKey, transcriptHash []byte, scheme SignatureScheme) ([]byte, error) {
	content := make([]byte, 64)
	for i := range content {
		content[i] = 0x20
	}
	content = append(content, "TLS 1.3, server CertificateVerify"...)
	content = append(content, 0x00)
	content = append(content, transcriptHash...)

	hash := sha256.Sum256(content)
	digest := hash[:]

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer")
	}

	var opts crypto.SignerOpts
	switch scheme {
	case ECDSA_SECP256R1_SHA256:
		opts = crypto.SHA256
	case RSASSA_PSS_RSAE_SHA256:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	default:
		return nil, errors.New("unsupported signature scheme")
	}

	return signer.Sign(rand.Reader, digest, opts)
}

func marshalCertificateVerify(signature []byte, scheme SignatureScheme) []byte {
	var buf []byte
	schemeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(schemeBytes, uint16(scheme))
	buf = append(buf, schemeBytes...)
	sigLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sigLen, uint16(len(signature)))
	buf = append(buf, sigLen...)
	buf = append(buf, signature...)
	return buf
}

func unmarshalCertificateVerify(data []byte) (signature []byte, scheme SignatureScheme, err error) {
	if len(data) < 4 {
		return nil, 0, errors.New("data too short for CertificateVerify")
	}
	scheme = SignatureScheme(binary.BigEndian.Uint16(data[0:2]))
	sigLen := binary.BigEndian.Uint16(data[2:4])
	if len(data) < int(4+sigLen) {
		return nil, 0, errors.New("data too short for CertificateVerify signature")
	}
	signature = make([]byte, sigLen)
	copy(signature, data[4:4+sigLen])
	return signature, scheme, nil
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

func readClientHello(clientHelloData []byte) (*client_hello.ClientHello, error) {
	clientHello := client_hello.ClientHello{}

	_, err := clientHello.Parse(clientHelloData)
	if err != nil {
		return nil, err
	}

	if clientHello.ClientHelloState != int(client_hello.ClientHelloCompleted) {
		return nil, errors.New("incomplete ClientHello data")
	}

	return &clientHello, nil
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
