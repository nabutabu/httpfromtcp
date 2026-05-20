package tls13

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"hash"
	"httpFromTcp/internal/tls13/client_hello"
	"io"
	"log"
	"net"
	"time"
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
	rawConn net.Conn
	config  *Config
	state   serverState
	reader  *bufio.Reader

	// Handshake state
	transcriptHash        hash.Hash
	serverHsTrafficSecret []byte
	clientHsTrafficSecret []byte

	// Record protection
	readKeys    *CipherKeys
	writeKeys   *CipherKeys
	readSeqNum  uint64
	writeSeqNum uint64

	// Buffered plaintext not yet consumed by Read()
	readBuf bytes.Buffer
}

func NewServerConn(rawConn net.Conn, config *Config) *Conn {
	return &Conn{
		rawConn: rawConn,
		reader:  bufio.NewReader(rawConn),
		config:  config,
		state:   stateExpectClientHello,
	}
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
	// -------------------------------------------------------------------------
	// Phase 1: Read ClientHello
	// -------------------------------------------------------------------------
	contentType, data, err := readRecord(c.reader)
	if err != nil {
		return err
	}
	if contentType != ContentTypeHandshake {
		return errors.New("expected handshake record")
	}
	if data[0] != 0x01 {
		return errors.New("expected ClientHello")
	}

	clientHello, err := readClientHello(data[4:])
	if err != nil {
		return err
	}

	c.transcriptHash = sha256.New()
	c.transcriptHash.Write(data) // feed full handshake bytes (header + body)

	// -------------------------------------------------------------------------
	// Phase 2: ECDHE key exchange
	// -------------------------------------------------------------------------
	var curve CurveID
	var clientPubKey []byte
	for _, ks := range clientHello.KeyShare {
		if ks.Group == 0x001D { // X25519 preferred
			curve, clientPubKey = CurveID(ks.Group), ks.KeyExchange
			break
		} else if ks.Group == 0x0017 { // P-256 fallback
			curve, clientPubKey = CurveID(ks.Group), ks.KeyExchange
		}
	}

	privKey, pubKey, err := GenerateKeyShare(curve)
	if err != nil {
		return err
	}

	sharedSecret, err := ComputeSharedSecret(privKey, clientPubKey, curve)
	if err != nil {
		return err
	}

	// -------------------------------------------------------------------------
	// Phase 2: Key schedule — up to HandshakeSecret
	// -------------------------------------------------------------------------
	log.Println("Phase 2: Key schedule up to handshake secret")
	earlySecret := DeriveEarlySecret(make([]byte, 32))
	handshakeSecret := DeriveHandshakeSecret(earlySecret, sharedSecret)

	// -------------------------------------------------------------------------
	// Phase 3: Build and send ServerHello (plaintext)
	// -------------------------------------------------------------------------
	log.Println("Phase 3")
	var serverRandom [32]byte
	if _, err = rand.Read(serverRandom[:]); err != nil {
		return err
	}

	serverHelloBody := NewServerHello(serverRandom, clientHello.LegacySessionID, 0x1301, client_hello.KeyShareEntry{
		Group:       uint16(curve),
		KeyExchange: pubKey,
	})
	serverHello := buildHandshakeMessage(0x02, serverHelloBody)

	c.transcriptHash.Write(serverHello)

	// Snapshot after ServerHello — used to derive handshake traffic secrets
	snapshotAfterServerHello := c.transcriptHash.Sum(nil)

	c.serverHsTrafficSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", snapshotAfterServerHello, 32, sha256.New)
	c.clientHsTrafficSecret = hkdfExpandLabel(handshakeSecret, "c hs traffic", snapshotAfterServerHello, 32, sha256.New)

	serverHsKeys := DeriveTrafficKeys(c.serverHsTrafficSecret)
	clientHsKeys := DeriveTrafficKeys(c.clientHsTrafficSecret)

	if err := writeRecord(c.rawConn, ContentTypeHandshake, serverHello); err != nil {
		return err
	}

	// Middlebox compatibility: send ChangeCipherSpec before encrypted records
	if err := writeRecord(c.rawConn, ChangeCipherSpec, []byte{0x01}); err != nil {
		return err
	}

	// Arm write path — everything from here is encrypted
	c.writeKeys = &serverHsKeys

	// -------------------------------------------------------------------------
	// Phase 4: Encrypted server flight
	// -------------------------------------------------------------------------
	log.Println("Phase 4")
	// 4.2 EncryptedExtensions (empty)
	encryptedExtensions := []byte{0x08, 0x00, 0x00, 0x02, 0x00, 0x00}
	c.transcriptHash.Write(encryptedExtensions)
	if err := c.writeEncryptedRecord(ContentTypeHandshake, encryptedExtensions); err != nil {
		return err
	}

	// 4.3 Certificate
	certHandshake, err := c.buildCertificateMessage()
	if err != nil {
		return err
	}
	c.transcriptHash.Write(certHandshake)
	if err := c.writeEncryptedRecord(ContentTypeHandshake, certHandshake); err != nil {
		return err
	}

	// 4.4 CertificateVerify
	var scheme SignatureScheme
	switch c.config.Certificate.PrivateKey.(type) {
	case *rsa.PrivateKey:
		scheme = RSASSA_PSS_RSAE_SHA256
	case *ecdsa.PrivateKey:
		scheme = ECDSA_SECP256R1_SHA256
	default:
		return errors.New("unsupported private key type")
	}

	transcriptForCertVerify := c.transcriptHash.Sum(nil)
	signature, err := signCertificateVerify(c.config.Certificate.PrivateKey, transcriptForCertVerify, scheme)
	if err != nil {
		return err
	}

	certVerifyHandshake := buildHandshakeMessage(0x0F, marshalCertificateVerify(signature, scheme))
	c.transcriptHash.Write(certVerifyHandshake)
	if err := c.writeEncryptedRecord(ContentTypeHandshake, certVerifyHandshake); err != nil {
		return err
	}

	// 4.5 Server Finished
	snapshotBeforeServerFinished := c.transcriptHash.Sum(nil)
	serverFinishedKey := computeFinishedKey(c.serverHsTrafficSecret)
	serverVerifyData := computeVerifyData(serverFinishedKey, snapshotBeforeServerFinished)

	serverFinished := buildHandshakeMessage(0x14, serverVerifyData)
	c.transcriptHash.Write(serverFinished)
	if err := c.writeEncryptedRecord(ContentTypeHandshake, serverFinished); err != nil {
		return err
	}

	// -------------------------------------------------------------------------
	// Phase 5: Derive application traffic keys
	// -------------------------------------------------------------------------
	log.Println("Phase 5")
	// Snapshot AFTER server Finished is in the transcript — required for app secrets
	snapshotAfterServerFinished := c.transcriptHash.Sum(nil)

	masterSecret := DeriveMasterSecret(handshakeSecret)
	clientAppSecret := hkdfExpandLabel(masterSecret, "c ap traffic", snapshotAfterServerFinished, 32, sha256.New)
	serverAppSecret := hkdfExpandLabel(masterSecret, "s ap traffic", snapshotAfterServerFinished, 32, sha256.New)

	clientAppKeys := DeriveTrafficKeys(clientAppSecret)
	serverAppKeys := DeriveTrafficKeys(serverAppSecret)

	// Switch write path to application keys
	c.writeKeys = &serverAppKeys
	c.writeSeqNum = 0

	// -------------------------------------------------------------------------
	// Phase 5: Read and verify client Finished
	// -------------------------------------------------------------------------
	log.Println("Reading multiple records now")
	// Discard optional ChangeCipherSpec
	nextContentType, nextData, err := readRecord(c.reader)
	if err != nil {
		return err
	}
	if nextContentType == ChangeCipherSpec {
		nextContentType, nextData, err = readRecord(c.reader)
		if err != nil {
			return err
		}
	}

	// Decrypt client Finished using client handshake traffic keys
	_, clientFinishedPlaintext, err := Decrypt(clientHsKeys, c.readSeqNum, nextData)
	if err != nil {
		return err
	}
	c.readSeqNum++

	// Snapshot BEFORE client Finished is in the transcript
	snapshotForClientFinished := c.transcriptHash.Sum(nil)

	clientFinishedKey := hkdfExpandLabel(c.clientHsTrafficSecret, "finished", []byte{}, sha256.New().Size(), sha256.New)
	expectedVerifyData := computeVerifyData(clientFinishedKey, snapshotForClientFinished)

	// extract verify_data: skip 4-byte handshake header (type + 3-byte length)
	receivedVerifyData := clientFinishedPlaintext[4:]

	if subtle.ConstantTimeCompare(expectedVerifyData, receivedVerifyData) == 0 {
		return errors.New("client Finished verification failed: handshake integrity check failed")
	}

	c.transcriptHash.Write(clientFinishedPlaintext)

	// Switch read path to application keys
	c.readKeys = &clientAppKeys
	c.readSeqNum = 0

	c.state = stateConnected
	return nil
}

// buildHandshakeMessage prepends the 4-byte handshake header (type + 3-byte length) to body.
func buildHandshakeMessage(msgType byte, body []byte) []byte {
	header := []byte{
		msgType,
		byte(len(body) >> 16),
		byte(len(body) >> 8),
		byte(len(body)),
	}
	return append(header, body...)
}

// buildCertificateMessage constructs the Certificate handshake message from c.config.
func (c *Conn) buildCertificateMessage() ([]byte, error) {
	var certMsg []byte
	certMsg = append(certMsg, 0x00) // empty certificate_request_context

	var certList []byte
	for _, der := range c.config.Certificate.Certificate {
		certList = append(certList,
			byte(len(der)>>16),
			byte(len(der)>>8),
			byte(len(der)),
		)
		certList = append(certList, der...)
		certList = append(certList, 0x00, 0x00) // empty per-cert extensions
	}

	certMsg = append(certMsg,
		byte(len(certList)>>16),
		byte(len(certList)>>8),
		byte(len(certList)),
	)
	certMsg = append(certMsg, certList...)

	return buildHandshakeMessage(0x0B, certMsg), nil
}

func (c *Conn) Close() error {
	return c.rawConn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.rawConn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.rawConn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.rawConn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.rawConn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.rawConn.SetWriteDeadline(t)
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	contentType, data, err := readRecord(c.reader)
	if err != nil {
		return 0, err
	}

	if contentType == Alert {
		return 0, io.EOF
	}

	if contentType != ApplicationData {
		return 0, errors.New("tls13: unexpected content type")
	}

	_, plaintext, err := Decrypt(*c.readKeys, c.readSeqNum, data)
	if err != nil {
		return 0, err
	}
	c.readSeqNum++

	c.readBuf.Write(plaintext)
	return c.readBuf.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.writeEncryptedRecord(ApplicationData, b); err != nil {
		return 0, err
	}
	return len(b), nil
}
