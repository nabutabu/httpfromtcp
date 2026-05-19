package tls13

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"hash"
	"httpFromTcp/internal/tls13/client_hello"
	"net"
)

type serverState int

const (
	stateExpectClientHello serverState = iota
	stateWaitCCS
	stateConnected
)

type Config struct {
	Certificate tls.Certificate // loaded via crypto/tls (just for parsing)
}

type Conn struct {
	rawConn      net.Conn
	config       *Config
	state        serverState
	handshakeErr error

	// Handshake state
	clientHello            *client_hello.ClientHello
	transcriptHash         hash.Hash // running SHA-256, updated as messages are sent/received
	serverRandom           [32]byte
	ecdhePrivate           []byte
	keys                   *KeySet
	serverHsTrafficSecret  []byte

	// Record protection
	readKeys    *CipherKeys
	writeKeys   *CipherKeys
	readSeqNum  uint64
	writeSeqNum uint64

	// Buffered data
	readBuf bytes.Buffer // decrypted but not yet consumed
}

func (c *Conn) writeEncryptedRecord(contentType ContentType, data []byte) error {
	ciphertext, err := Encrypt(*c.writeKeys, c.writeSeqNum, byte(contentType), data)
	if err != nil {
		return err
	}

	if err := writeRecord(c.rawConn, ApplicationData, ciphertext); err != nil {
		return err
	}

	c.writeSeqNum++
	return nil
}

func (c *Conn) Handshake() error {
	for {
		contentType, data, err := readRecord(c.rawConn)
		if err != nil {
			return err
		}

		if contentType == ContentTypeHandshake {
			// get handshake type from first byte
			handshakeType := data[0]
			if handshakeType != 0x01 {
				return errors.New("invalid handshake type")
			}

			// get client hello
			// first 4 bytes of data = handshakeType (1) + length (3)
			clientHelloRaw := data[4:]
			clientHello, err := readClientHello(clientHelloRaw)
			if err != nil {
				return err
			}

			c.transcriptHash = sha256.New()
			c.transcriptHash.Write(data)

			// find what curve client offered in keyshare
			// take the first one that you see between X25519 and secp256r1
			var curve CurveID
			var clientPubKey []byte
			for _, ks := range clientHello.KeyShare {
				if ks.Group == 0x001D { // X25519 — preferred
					curve = CurveID(ks.Group)
					clientPubKey = ks.KeyExchange
					break
				} else if ks.Group == 0x0017 { // P-256 — fallback
					curve = CurveID(ks.Group)
					clientPubKey = ks.KeyExchange
				}
			}

			// generate Key share
			privKey, pubKey, err := GenerateKeyShare(curve)
			if err != nil {
				return err
			}

			// store privKey
			c.ecdhePrivate = privKey

			// create shared secret
			sharedSecret, err := ComputeSharedSecret(privKey, clientPubKey, curve)
			if err != nil {
				return err
			}

			// KeySchedule
			earlySecret := DeriveEarlySecret(make([]byte, 32))
			handshakeSecret := DeriveHandshakeSecret(earlySecret, sharedSecret)


			// create serverHello
			var serverRandom [32]byte
			if _, err = rand.Read(serverRandom[:]); err != nil {
				return err
			}
			serverHelloRaw := NewServerHello(serverRandom, clientHello.LegacySessionID, 0x1301, client_hello.KeyShareEntry{
				Group: uint16(curve),
				KeyExchange: pubKey,
			})

			serverHello := append([]byte{0x02, byte(len(serverHelloRaw) >> 16), byte(len(serverHelloRaw) >> 8), byte(len(serverHelloRaw))}, serverHelloRaw...)

			c.transcriptHash.Write(serverHello)

			snapshot := c.transcriptHash.Sum(nil)

			c.serverHsTrafficSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", snapshot, 32, sha256.New)
			clientHsTrafficSecret := hkdfExpandLabel(handshakeSecret, "c hs traffic", snapshot, 32, sha256.New)

			serverHsKeys := DeriveTrafficKeys(c.serverHsTrafficSecret)
			clientHsKeys := DeriveTrafficKeys(clientHsTrafficSecret)

			c.writeKeys = &serverHsKeys
			c.readKeys = &clientHsKeys
			
			// Wrap ServerHello in a TLS record and write it
			if err := writeRecord(c.rawConn, ContentTypeHandshake, serverHello); err != nil {
				return err
			}

			// Send a ChangeCipherSpec record
			if err := writeRecord(c.rawConn, ChangeCipherSpec, []byte{0x01}); err != nil {
				return err
			}

			// Construct and send EncryptedExtensions
			extensionsRaw := []byte{0x08, 0x00, 0x00, 0x02, 0x00, 0x00}

			c.transcriptHash.Write(extensionsRaw)

			if err := c.writeEncryptedRecord(ContentTypeHandshake, extensionsRaw); err != nil {
				return err
			}

			// Construct and send Certificate
			var certMsg []byte
			certMsg = append(certMsg, 0x00) // empty certificate_request_context

			var certList []byte
			for _, der := range c.config.Certificate.Certificate {
				certList = append(certList, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
				certList = append(certList, der...)
				certList = append(certList, 0x00, 0x00) // no extensions
			}

			certMsg = append(certMsg, byte(len(certList)>>16), byte(len(certList)>>8), byte(len(certList)))
			certMsg = append(certMsg, certList...)

			certHandshake := append([]byte{0x0B}, byte(len(certMsg)>>16), byte(len(certMsg)>>8), byte(len(certMsg)))
			certHandshake = append(certHandshake, certMsg...)

			c.transcriptHash.Write(certHandshake)

			if err := c.writeEncryptedRecord(ContentTypeHandshake, certHandshake); err != nil {
				return err
			}
			
			// Construct and send CertificateVerify
			transcriptSoFar := c.transcriptHash.Sum(nil)

			var scheme SignatureScheme
			switch c.config.Certificate.PrivateKey.(type) {
			case *rsa.PrivateKey:
				scheme = RSASSA_PSS_RSAE_SHA256
			case *ecdsa.PrivateKey:
				scheme = ECDSA_SECP256R1_SHA256
			default:
				return errors.New("unsupported private key type")
			}

			signature, err := signCertificateVerify(c.config.Certificate.PrivateKey, transcriptSoFar, scheme)
			if err != nil {
				return err
			}

			certVerifyBody := marshalCertificateVerify(signature, scheme)
			certVerifyHandshake := append([]byte{0x0F, byte(len(certVerifyBody) >> 16), byte(len(certVerifyBody) >> 8), byte(len(certVerifyBody))}, certVerifyBody...)

			c.transcriptHash.Write(certVerifyHandshake)

			if err := c.writeEncryptedRecord(ContentTypeHandshake, certVerifyHandshake); err != nil {
				return err
			}
			
			// Compute and send server Finished
			snapshot = c.transcriptHash.Sum(nil)
			finishedKey := computeFinishedKey(c.serverHsTrafficSecret)
			verifyData := computeVerifyData(finishedKey, snapshot)

			finishedHandshake := append([]byte{0x14, byte(len(verifyData) >> 16), byte(len(verifyData) >> 8), byte(len(verifyData))}, verifyData...)

			c.transcriptHash.Write(finishedHandshake)

			if err := c.writeEncryptedRecord(ContentTypeHandshake, finishedHandshake); err != nil {
				return err
			}
			
		}
	}
	return nil
}
