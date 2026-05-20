# TLS 1.3 Implementation Plan (from scratch)

Build a `internal/tls13/` package implementing the server side of TLS 1.3 (RFC 8446) using Go's lower-level crypto primitives only — **not** `crypto/tls`.

---

## Prerequisites

Understand: TLS 1.3 handshake flow, record layer, AEAD encryption, HKDF key schedule, ECDHE.

### What we use from Go stdlib

| Package                     | Usage                               |
|-----------------------------|-------------------------------------|
| `crypto/aes`                | AES block cipher                    |
| `crypto/cipher`             | AES-GCM AEAD                        |
| `crypto/elliptic`           | P-256 curve params                  |
| `crypto/ecdh`               | ECDH key exchange (Go 1.20+)        |
| `crypto/ecdsa`              | (optional) CertificateVerify signing|
| `crypto/rsa`                | (optional) CertificateVerify signing|
| `crypto/rand`               | Random nonces, key gen              |
| `crypto/sha256`             | Transcript hash, key schedule       |
| `crypto/hkdf`               | HKDF-Extract and HKDF-Expand        |
| `crypto/x509`               | Parse certificate                   |
| `crypto/hmac`               | HMAC for Finished, key schedule     |

### What we avoid

`crypto/tls` — the entire point is reimplementing TLS 1.3 ourselves.

---

## Scope

### Implement

- Full TLS 1.3 server handshake (RFC 8446)
- `TLS_AES_128_GCM_SHA256` (0x1301)
- X25519 or P-256 ECDHE key exchange
- X.509 server certificate
- Server CertificateVerify (RSA-PSS or ECDSA)
- Finished message (send and verify)
- Application data record encryption/decryption
- Transcript hash integrity

### Defer (future)

- Client certificates (mTLS)
- ChaCha20-Poly1306 cipher suite
- PSK / 0-RTT
- Session tickets / resumption
- HelloRetryRequest
- KeyUpdate
- OCSP stapling
- Ed25519 signatures

---

## Architecture

### How it plugs into the server

```
handle(conn net.Conn):
  1. tlsConn := tls13.NewServerConn(conn, config)  // wrap raw TCP conn
  2. tlsConn.Handshake()                             // do TLS 1.3 handshake
  3. req := request.RequestFromReader(tlsConn)       // read through decrypt
  4. handler(tlsConn, req)                           // write through encrypt
```

`tls13.Conn` implements `io.ReadWriter`:

```
Read(p []byte)  → decrypts a TLS record, copies plaintext to p
Write(p []byte) → encrypts p into a TLS record, writes to raw conn
```

---

## Implementation Steps

### Step 1 — Package skeleton & TLS record layer

**File:** `internal/tls13/record.go`
**Depends on:** nothing

A TLS record has a 5-byte header:

```
ContentType (1) | LegacyVersion (2) | Length (2) | Fragment (variable)
```

Content types:

| Code | Name                                      |
|------|-------------------------------------------|
| 20   | ChangeCipherSpec (must be silently ignored in 1.3) |
| 21   | Alert                                     |
| 22   | Handshake                                 |
| 23   | Application Data                          |

Implement:

```go
func readRecord(r io.Reader) (contentType byte, data []byte, err error)
func writeRecord(w io.Writer, contentType byte, data []byte) error
```

Start with plaintext records. Encryption gets added in Step 5.

**⚠️ Pitfall — ChangeCipherSpec middlebox compatibility:**
TLS 1.3 clients (curl, browsers, Go's crypto/tls) frequently send a `ChangeCipherSpec` (content type 20) record between ClientHello and the first encrypted message. This is a deliberate middlebox compatibility measure described in RFC 8446 §D.4 — the client isn't actually changing cipher specs, it's just sending a legacy signal to confuse intermediaries that expect TLS 1.2. Your record reader **must** silently discard these records rather than treating them as errors. The right place to do this is inside `readRecord` itself, so all callers are protected:

```go
for {
    contentType, data, err := readRawRecord(r)
    if err != nil {
        return 0, nil, err
    }
    if contentType == 20 { // ChangeCipherSpec — discard, RFC 8446 §D.4
        continue
    }
    return contentType, data, nil
}
```

If you miss this, every real client will fail with a confusing and hard to diagnose error.

**Test:** Round-trip a record through `bytes.Buffer`. Verify header parsing. Also write a test that feeds a ChangeCipherSpec record followed by a Handshake record and confirms only the Handshake record is returned.

**Resources:**
- RFC 8446 §5: [Record Protocol](https://datatracker.ietf.org/doc/html/rfc8446#section-5)
- RFC 8446 §5.1: [Record Layer](https://datatracker.ietf.org/doc/html/rfc8446#section-5.1)
- RFC 8446 §D.4: [Middlebox Compatibility Mode](https://datatracker.ietf.org/doc/html/rfc8446#appendix-D.4)

---

### Step 2 — Handshake message framing & ClientHello parsing

**File:** `internal/tls13/handshake.go`
**Depends on:** Step 1

Handshake messages are framed inside records:

```
HandshakeType (1) | Length (3) | Message (variable)
```

Handshake types:

| Code | Type                 | Server role     |
|------|----------------------|-----------------|
| 1    | ClientHello          | parse (incoming)|
| 2    | ServerHello          | construct (out) |
| 8    | EncryptedExtensions  | construct (out) |
| 11   | Certificate          | construct (out) |
| 15   | CertificateVerify    | construct (out) |
| 20   | Finished             | construct (out) and parse (in) |

Implement:

```go
type Handshake struct {
    MsgType byte
    Data    []byte
}

func readHandshake(r io.Reader) (*Handshake, error)
func writeHandshake(w io.Writer, msgType byte, data []byte) error
```

Then implement **ClientHello parsing** — the most complex struct to parse:

```go
type ClientHello struct {
    LegacyVersion       [2]byte
    Random              [32]byte
    LegacySessionID     []byte
    CipherSuites        []uint16
    LegacyCompression   []byte
    Extensions          []Extension
}
```

Minimum extensions to parse:
- `supported_versions` (type 43) — confirm TLS 1.3 (0x0304)
- `key_share` (type 51) — extract client's ephemeral public key(s)
- `supported_groups` (type 10) — optional, verify curve support

```go
type Extension struct {
    Type   uint16
    Data   []byte
}
```

Parse key_share entries:

```go
type KeyShareEntry struct {
    Group   uint16    // 0x001D = X25519, 0x0017 = secp256r1
    KeyData []byte    // public key
}
```

**⚠️ Pitfall — `key_share` is a list, not a single entry:**
The client sends a `ClientShares` vector — potentially multiple `KeyShareEntry` structs for different groups (e.g. X25519 and P-256). Your parser must iterate the entire list and select the first group your server supports. Do not assume a single entry. If no supported group is present, the correct protocol response is a `HelloRetryRequest`, which is out of scope for now — return a clear error instead. The wire format is:

```
key_share extension data:
  client_shares length (2 bytes)
  [
    NamedGroup (2 bytes)
    key_exchange length (2 bytes)
    key_exchange data (variable)
  ] * N
```

**Test:** Construct a raw ClientHello byte slice (with multiple key_share entries), parse it, verify all fields and that the correct entry is selected.

**Resources:**
- RFC 8446 §4: [Handshake Protocol](https://datatracker.ietf.org/doc/html/rfc8446#section-4)
- RFC 8446 §4.1.2: [ClientHello](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2)
- RFC 8446 §4.2.8: [Key Share](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8)
- RFC 8446 §4.2.1: [Supported Versions](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1)

---

### Step 3 — Key schedule (HKDF-based)

**File:** `internal/tls13/key_schedule.go`
**Depends on:** nothing (pure math, no network)

This is the heart of TLS 1.3. Implement HKDF wrappers:

```go
func hkdfExtract(salt, ikm []byte, hash func() hash.Hash) []byte
func hkdfExpandLabel(secret []byte, label string, context []byte, length int, hash func() hash.Hash) []byte
```

`hkdfExpandLabel` composes `hkdf.Expand` with TLS label formatting. The input to HKDF-Expand is an encoded `HkdfLabel` struct (RFC 8446 §7.1):

```
struct {
    uint16 length;          // 2 bytes big-endian: the desired output length
    opaque label<7..255>;   // 1-byte length prefix, then "tls13 " + label_string
    opaque context<0..255>; // 1-byte length prefix, then the context bytes
}
```

**⚠️ Pitfall — HkdfLabel encoding is extremely fiddly:**
There are three distinct length values packed into this struct and they are easy to confuse:
- `length` (2 bytes): the *output* byte length you want from HKDF-Expand
- the label field's 1-byte prefix: the byte length of `"tls13 " + label_string`
- the context field's 1-byte prefix: the byte length of `context`

Getting any one of these wrong produces a completely different key with no error — the key schedule will silently diverge from the expected values. **Test this function in isolation against RFC 8448 vectors before writing anything else in this file.** It is the foundation everything else rests on.

Key schedule (RFC 8446 §7.1):

```
           0
           |
           v
  PSK -> HKDF-Extract = Early Secret
           |
           +-----> Derive-Early Secret
           +-----> Derive-Secret(., "derived", "")
           |
           v
  (EC)DHE -> HKDF-Extract = Handshake Secret
           |
           +-----> Derive-Secret(., "s hs traffic", ...)
           +-----> Derive-Secret(., "c hs traffic", ...)
           +-----> Derive-Secret(., "derived", "")
           |
           v
          0 -> HKDF-Extract = Master Secret
           |
           +-----> Derive-Secret(., "s ap traffic", ...)
           +-----> Derive-Secret(., "c ap traffic", ...)
```

Implement:

```go
type KeySet struct {
    ClientHandshakeTrafficSecret   []byte
    ServerHandshakeTrafficSecret   []byte
    ClientApplicationTrafficSecret []byte
    ServerApplicationTrafficSecret []byte
    ServerHandshakeKeys            CipherKeys
    ServerApplicationKeys          CipherKeys
    ClientHandshakeKeys            CipherKeys
    ClientApplicationKeys          CipherKeys
    ResumptionMasterSecret         []byte
}

type CipherKeys struct {
    Key []byte   // 16 bytes for AES-128
    Iv  []byte   // 12 bytes
}

func DeriveEarlySecret(psk []byte) []byte
func DeriveHandshakeSecret(earlySecret, sharedSecret []byte) []byte
func DeriveMasterSecret(handshakeSecret []byte) []byte
func DeriveTrafficKeys(secret []byte, label string, transcriptHash []byte) CipherKeys
```

Label values:

| Derive-Secret label           | Purpose                        |
|-------------------------------|--------------------------------|
| `"c hs traffic"`             | Client handshake traffic keys  |
| `"s hs traffic"`             | Server handshake traffic keys  |
| `"c ap traffic"`             | Client application traffic keys|
| `"s ap traffic"`             | Server application traffic keys|
| `"key"`                      | AEAD key (via ExpandLabel)     |
| `"iv"`                       | AEAD IV/nonce (via ExpandLabel)|
| `"res master"`               | Resumption master secret       |
| `"derived"`                  | Derive intermediate secret     |

**Test:** Test `hkdfExpandLabel` encoding first in isolation, then use RFC 8448 test vectors for the full key schedule. Every intermediate value (early secret, handshake secret, master secret, each traffic key and IV) has a known-good expected value. Verify each one with a unit test before proceeding.

**Resources:**
- RFC 8446 §7.1: [Key Schedule](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
- RFC 8448: [Example Handshake Traces](https://datatracker.ietf.org/doc/html/rfc8448) — **critical test vectors**
- Go docs: [`crypto/hkdf`](https://pkg.go.dev/crypto/hkdf)

---

### Step 4 — ECDHE key exchange

**File:** `internal/tls13/key_exchange.go`
**Depends on:** nothing (pure math)

The client sends their ephemeral public key in `key_share`. The server generates its own and computes the shared secret.

```go
type CurveID uint16

const (
    X25519    CurveID = 0x001D
    P256      CurveID = 0x0017
)

func GenerateKeyShare(curveID CurveID) (privateKey []byte, publicKey []byte, err error)
func ComputeSharedSecret(privateKey, peerPublic []byte, curveID CurveID) ([]byte, error)
func MarshalPublicKey(publicKey []byte, curveID CurveID) []byte
func UnmarshalPublicKey(data []byte, curveID CurveID) ([]byte, error)
```

For P-256 use `crypto/ecdh.P256()`. For X25519, use `crypto/ecdh.X25519()`.

The server stores the private key ephemerally — it is used exactly once per handshake then discarded.

**Test:** Bob and Alice each generate a keypair. Exchange public keys. Verify both compute the identical shared secret.

**Resources:**
- RFC 8446 §7.4: [ECDHE](https://datatracker.ietf.org/doc/html/rfc8446#section-7.4)
- RFC 8446 §4.2.8: [Key Share](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8)
- Go docs: [`crypto/ecdh`](https://pkg.go.dev/crypto/ecdh)

---

### Step 5 — AEAD encryption (record protection)

**File:** `internal/tls13/cipher.go`
**Depends on:** Step 3 (Keys structure)

Implement TLS 1.3 record encryption and decryption.

```go
func Encrypt(keys CipherKeys, seqNum uint64, contentType byte, plaintext []byte) (ciphertext []byte, err error)
func Decrypt(keys CipherKeys, seqNum uint64, aadContentType byte, ciphertext []byte) (plaintext []byte, err error)
```

AES-128-GCM details:

- **Nonce**: `keys.Iv` XOR `seqNum` (seqNum as uint64 → 8 bytes → left-padded with 0s to 12 bytes)
- **AAD**: `contentType (1) || legacyVersion (2, 0x0303) || length (2)` — 5 bytes total
- **Inner content type**: The last non-zero byte of the plaintext before encryption is the actual content type (e.g. 22 for handshake, 23 for app data)
- **Outer content type**: Always 23 (Application Data) for encrypted records

**⚠️ Pitfall — inner content type stripping on decrypt:**
When decrypting, the last byte of the plaintext is the real content type. However, the sender may add zero-byte padding *before* the content type byte (trailing zeros in the plaintext, with the content type at the end). You cannot simply strip the last byte — you must strip all trailing `0x00` bytes, and the *last non-zero byte* is the actual content type. Stripping exactly one byte unconditionally is wrong and will cause failures with padded records:

```go
// strip trailing zeros, last non-zero byte is the inner content type
i := len(plaintext) - 1
for i >= 0 && plaintext[i] == 0 {
    i--
}
if i < 0 {
    return nil, 0, errors.New("no content type byte found")
}
innerContentType := plaintext[i]
plaintext = plaintext[:i]
```

**Test:** RFC 8448 provides specific ciphertext/plaintext pairs with known keys and sequence numbers. Verify encrypt and decrypt both match.

**Resources:**
- RFC 8446 §5.2: [Record Payload Protection](https://datatracker.ietf.org/doc/html/rfc8446#section-5.2)
- RFC 8446 §5.3: [Per-Record Nonce](https://datatracker.ietf.org/doc/html/rfc8446#section-5.3)
- Go docs: [`crypto/aes`](https://pkg.go.dev/crypto/aes), [`crypto/cipher.NewGCM`](https://pkg.go.dev/crypto/cipher#NewGCM)

---

### Step 6a — ServerHello construction

**File:** `internal/tls13/handshake.go` (extend)
**Depends on:** Step 2 (framing), Step 4 (ECDHE public key)

Construct the ServerHello message. This is sent in plaintext so it can be tested without encryption.

```go
type ServerHello struct {
    LegacyVersion     [2]byte  // always 0x0303
    Random            [32]byte
    LegacySessionID   []byte   // echo client's session ID
    CipherSuite       [2]byte  // 0x1301 for TLS_AES_128_GCM_SHA256
    LegacyCompression byte     // 0x00
    Extensions        []Extension
}

func NewServerHello(random [32]byte, sessionID []byte, cipherSuite uint16, keyShare KeyShareEntry) []byte
```

Required extensions in ServerHello:
- `supported_versions` (type 43): value `0x0304` to signal TLS 1.3
- `key_share` (type 51): the server's chosen group and ephemeral public key

**Test:** Construct a ServerHello, marshal it to bytes, parse those bytes back, verify all fields round-trip correctly.

**Resources:**
- RFC 8446 §4.1.3: [ServerHello](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3)

---

### Step 6b — CertificateVerify signing

**File:** `internal/tls13/handshake.go` (extend)
**Depends on:** Step 3 (transcript hash)

The server signs the transcript hash with its private key. This is pure crypto with no network involvement, so it can be tested in complete isolation.

Signature input (RFC 8446 §4.4.3):

```
content = 0x20 * 64               // 64 space bytes (0x20)
        + "TLS 1.3, server CertificateVerify"
        + 0x00                     // single null byte separator
        + TranscriptHash           // SHA-256 of all handshake messages so far
```

```go
type SignatureScheme uint16

const (
    RSASSA_PSS_RSAE_SHA256 SignatureScheme = 0x0804
    ECDSA_SECP256R1_SHA256 SignatureScheme = 0x0403
)

func signCertificateVerify(privKey crypto.PrivateKey, transcriptHash []byte, scheme SignatureScheme) ([]byte, error)
func marshalCertificateVerify(signature []byte, scheme SignatureScheme) []byte
func unmarshalCertificateVerify(data []byte) (signature []byte, scheme SignatureScheme, err error)
```

**Test:** Sign a known transcript hash with a known private key. Verify the signature using the corresponding public key. Also test marshal/unmarshal round-trip.

**Resources:**
- RFC 8446 §4.4.3: [CertificateVerify](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3)

---

### Step 6c — Finished message (send and verify)

**File:** `internal/tls13/handshake.go` (extend)
**Depends on:** Step 3 (key schedule)

The Finished message is an HMAC over the transcript hash, keyed with a "finished key" derived from the traffic secret.

```
finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", hash.Size)
verify_data  = HMAC-SHA256(finished_key, TranscriptHash)
```

```go
func computeFinishedKey(trafficSecret []byte) []byte
func computeVerifyData(finishedKey []byte, transcriptHash []byte) []byte
func marshalFinished(verifyData []byte) []byte
```

This same function is used twice in the handshake: once to produce the **server's** Finished, and once to verify the **client's** Finished (using the client handshake traffic secret as the base key, and the transcript hash at that point in time).

**⚠️ Important:** The transcript hash snapshot used for the client's Finished verification includes all messages up to and including the server's Finished message. Make sure you capture the hash at the right point — see the Transcript Hash note in Step 7.

**Test:** Use RFC 8448 test vectors. The expected `verify_data` bytes for both server and client Finished are provided there. Verify both.

**Resources:**
- RFC 8446 §4.4.4: [Finished](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4)
- RFC 8448: [Example Handshake Traces](https://datatracker.ietf.org/doc/html/rfc8448)

---

### Step 7 — TLS server connection (the state machine)

**File:** `internal/tls13/conn.go`
**Depends on:** Steps 1–6

This ties everything together into a `net.Conn`-like wrapper.

```go
type serverState int

const (
    stateExpectClientHello serverState = iota
    stateWaitCCS
    stateConnected
)

type Config struct {
    Certificate tls.Certificate  // loaded via crypto/tls (just for parsing)
}

type Conn struct {
    rawConn      net.Conn
    config       *Config
    state        serverState
    handshakeErr error

    // Handshake state
    clientHello     *ClientHello
    transcriptHash  hash.Hash    // running SHA-256, updated as messages are sent/received
    serverRandom    [32]byte
    ecdhePrivate    []byte
    keys            *KeySet

    // Record protection
    readKeys     *CipherKeys
    writeKeys    *CipherKeys
    readSeqNum   uint64
    writeSeqNum  uint64

    // Buffered data
    readBuf      bytes.Buffer  // decrypted but not yet consumed
}
```

#### Transcript Hash — threading and snapshot points

**⚠️ This is the single most common source of subtle bugs in a TLS implementation.**

The transcript hash is a *running* SHA-256 over the raw bytes of every handshake message in wire format (the `HandshakeType || Length(3) || body` bytes — not the record framing). Keep a single `hash.Hash` on the `Conn` struct and feed every message into it as it is sent or received.

The key schedule requires *snapshots* of this running hash at specific points. RFC 8446 §4.4.1 defines exactly which messages are included at each derivation point:

| Derivation                        | Transcript includes up to (and including) |
|-----------------------------------|-------------------------------------------|
| Server handshake traffic keys     | ServerHello                               |
| Client handshake traffic keys     | ServerHello                               |
| EncryptedExtensions through wire  | (use server hs traffic keys from above)   |
| Server Finished verify_data       | Certificate, CertificateVerify            |
| Server application traffic keys   | server Finished                           |
| Client application traffic keys   | server Finished                           |
| Client Finished verification      | server Finished                           |
| Resumption master secret          | client Finished                           |

To take a snapshot without disturbing the running hash, use `hash.Sum(nil)` — this returns the current digest without finalizing the hash object, so you can continue feeding bytes into it afterward.

Read RFC 8446 §4.4.1 carefully before writing the state machine. The spec states these snapshot rules explicitly and they are not optional.

#### Handshake() sequence

```go
func (c *Conn) Handshake() error
```

1. Read ClientHello record → parse ClientHello → feed raw bytes into transcript hash
2. Generate server ECDHE keypair
3. Compute ECDHE shared secret from client's key_share
4. Derive HandshakeSecret (feed ClientHello + ServerHello transcript snapshot into key schedule)
5. Construct ServerHello → feed raw bytes into transcript hash → write (plaintext)
6. Derive server + client handshake traffic keys (transcript snapshot at ServerHello)
7. Switch write path to encrypt with server handshake traffic keys
8. Construct EncryptedExtensions → feed into transcript → encrypt → write
9. Construct Certificate → feed into transcript → encrypt → write
10. Sign + construct CertificateVerify → feed into transcript → encrypt → write
11. Compute server Finished verify_data (transcript snapshot before server Finished) → feed Finished into transcript → encrypt → write
12. Derive server + client application traffic keys (transcript snapshot after server Finished)
13. Switch write path to application traffic keys
14. Read client's ChangeCipherSpec if present (discard silently — handled by readRecord from Step 1)
15. Read and decrypt client Finished → verify `verify_data` using client handshake traffic key and current transcript hash
16. If verification fails → return error (do not proceed)
17. Feed client Finished bytes into transcript hash
18. Switch read path to client application traffic keys
19. state = connected

**⚠️ Step 15–16 are not optional.** Accepting application data without verifying the client's Finished means you have not confirmed the client received the same handshake you sent. This breaks the handshake's integrity guarantee.

```go
func (c *Conn) Read(p []byte) (int, error)
//  - If readBuf has data, copy from there
//  - Otherwise, read a record from rawConn
//  - If encrypted, decrypt using readKeys and strip inner content type
//  - Return plaintext

func (c *Conn) Write(p []byte) (int, error)
//  - Encrypt p using writeKeys
//  - Wrap in application data record (outer content type 23)
//  - Write to rawConn

func (c *Conn) Close() error
```

The `readBuf` is important because the plaintext from one record may be larger than `p`, and the remainder must be buffered for the next `Read` call.

**Test:** Write a test using `net.Pipe()` (in-memory, no sockets). One goroutine runs your `tls13.Conn.Handshake()` as the server. The other goroutine uses Go's standard `crypto/tls` as the client, configured to skip certificate verification (`InsecureSkipVerify: true`) and requiring TLS 1.3 only (`MinVersion: tls.VersionTLS13`). If the handshake completes and both sides can exchange a request/response, the implementation is correct.

**Resources:**
- RFC 8446 §2: [Protocol Overview](https://datatracker.ietf.org/doc/html/rfc8446#section-2)
- RFC 8446 §4.4.1: [The Transcript Hash](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1)

---

### Step 8 — Capture and inspect with Wireshark

Before wiring into the server, validate the full handshake from a running process using packet capture.

```bash
# generate a self-signed cert if you haven't yet
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"

# start capture on loopback
tshark -i lo -w handshake.pcap port 42069

# in another terminal, run a standalone test binary using your tls13.Conn
# then connect with Go's crypto/tls client and log the key material:
SSLKEYLOGFILE=keys.log go test ./internal/tls13/... -run TestFullHandshake -v
```

Open `handshake.pcap` in Wireshark, go to `Edit → Preferences → Protocols → TLS`, and point the "(Pre)-Master-Secret log filename" at `keys.log`. Wireshark will decrypt the capture inline. You can then see exactly which message was malformed if the handshake fails, rather than guessing from error strings.

This step has no deliverable beyond a passing visual inspection. Move on once you can see a complete, decrypted TLS 1.3 handshake in Wireshark.

---

### Step 9 — Wire into `internal/server/server.go`

**File:** `internal/server/server.go`
**Depends on:** Step 7

Minimal changes:

```go
type Server struct {
    Addr           string
    Listener       net.Listener
    Handler        Handler
    TLSConfig      *tls13.Config   // nil = plain TCP, backward compatible
    IsServerClosed atomic.Bool
}

func (s *Server) handle(conn net.Conn) {
    if s.TLSConfig != nil {
        tlsConn := tls13.NewServerConn(conn, s.TLSConfig)
        if err := tlsConn.Handshake(); err != nil {
            log.Printf("TLS handshake failed: %v", err)
            conn.Close()
            return
        }
        conn = tlsConn
    }
    // rest of handle() unchanged...
}
```

When `TLSConfig` is nil, the server works exactly as before (plain TCP). This ensures backward compatibility.

---

### Step 10 — New entry point: `cmd/httpsserver/main.go`

**File:** `cmd/httpsserver/main.go`
**Depends on:** Step 9

Nearly identical to `cmd/httpserver/main.go`, but with TLS setup:

```go
package main

import (
    "crypto/tls"
    "httpFromTcp/internal/server"
    "httpFromTcp/internal/tls13"
    "log"
    "net"
    "os"
    "os/signal"
    "strconv"
    "syscall"
)

const port = 42069

func main() {
    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Fatalf("Failed to load certificate: %v", err)
    }

    config := &tls13.Config{Certificate: cert}

    listener, err := net.Listen("tcp", "localhost:"+strconv.Itoa(port))
    if err != nil {
        log.Fatalf("Error starting server: %v", err)
    }

    srv := &server.Server{
        Addr:      "localhost:" + strconv.Itoa(port),
        Listener:  listener,
        Handler:   handler,
        TLSConfig: config,
    }
    defer srv.Close()

    log.Println("HTTPS server started on port", port)

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan
    log.Println("Server gracefully stopped")
}
```

---

### Step 11 — End-to-end testing

```bash
# Terminal 1: start the server
go run ./cmd/httpsserver/

# Terminal 2: test with curl
curl -v --insecure https://localhost:42069/
```

Expected output (curtailed):

```
* SSL connection using TLSv1.3 / AES_128_GCM_SHA256
* ALPN: server accepted http/1.1
> GET / HTTP/1.1
> Host: localhost:42069
< HTTP/1.1 200 OK
...
```

If that works, also test the chunked encoding endpoints:

```bash
curl -v --insecure https://localhost:42069/httpbin/image/png -o out.png
```

---

## Testing strategy by step

| Step   | Test method                                                    |
|--------|----------------------------------------------------------------|
| 1      | Round-trip record through `bytes.Buffer`; ChangeCipherSpec discard test |
| 2      | Construct raw ClientHello with multiple key_share entries → parse → verify field selection |
| 3      | `hkdfExpandLabel` encoding in isolation first; then RFC 8448 vectors for full key schedule |
| 4      | Two keypairs → same shared secret                              |
| 5      | RFC 8448 vectors; test zero-padded plaintext stripping on decrypt |
| 6a     | ServerHello marshal/unmarshal round-trip                       |
| 6b     | Sign known transcript hash → verify with public key            |
| 6c     | RFC 8448 Finished verify_data vectors for both server and client |
| 7      | `net.Pipe()` + `crypto/tls` client (TLS 1.3 only, InsecureSkipVerify) |
| 8      | Wireshark capture with SSLKEYLOGFILE — visual inspection       |
| 9      | Existing plain-TCP tests still pass with nil TLSConfig         |
| 11     | `curl --insecure`; chunked endpoint                           |

**RFC 8448** provides the byte-exact handshake trace including every intermediate key — it is the single most valuable testing resource for steps 3, 5, 6b, and 6c.

---

## File plan

```
internal/
  tls13/
    types.go            constants (cipher suites, handshake types, content types, signature schemes)
    record.go           TLS record layer read/write (with ChangeCipherSpec discard)
    handshake.go        handshake message framing + ClientHello parsing + ServerHello/Cert/Finished construction
    key_schedule.go     HKDF-Extract, HKDF-Expand-Label, traffic key derivation
    key_exchange.go     ECDHE key generation, shared secret
    cipher.go           AEAD record encrypt/decrypt (with inner content type stripping)
    conn.go             Conn: Handshake(), Read(), Write(), Close()

internal/
  server/
    server.go           add TLSConfig field, wrap conn in handle()

cmd/
  httpsserver/
    main.go             new entry point with cert loading
```

---

## Reference material

| Resource | Link |
|----------|------|
| RFC 8446 (TLS 1.3) | https://datatracker.ietf.org/doc/html/rfc8446 |
| RFC 8446 §4.4.1 (Transcript Hash) | https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1 |
| RFC 8446 §D.4 (Middlebox compat) | https://datatracker.ietf.org/doc/html/rfc8446#appendix-D.4 |
| RFC 8448 (Test vectors) | https://datatracker.ietf.org/doc/html/rfc8448 |
| Go crypto/hkdf | https://pkg.go.dev/crypto/hkdf |
| Go crypto/ecdh | https://pkg.go.dev/crypto/ecdh |
| Go crypto/cipher (GCM) | https://pkg.go.dev/crypto/cipher#NewGCM |
| TLS 1.3 Handshake walkthrough (Cloudflare) | https://blog.cloudflare.com/rfc-8446-aka-tls-1-3/ |