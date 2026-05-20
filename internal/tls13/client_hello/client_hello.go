package client_hello

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type State int
type ExtensionType uint16

const (
	ClientHelloInitialized      State = 0
	ClientHelloVersionDone      State = 1
	ClientHelloRandomDone       State = 2
	ClientHelloSessionIDData    State = 3
	ClientHelloCipherSuitesLen  State = 4
	ClientHelloCipherSuitesData State = 5
	ClientHelloCompressionLen   State = 6
	ClientHelloCompressionData  State = 7
	ClientHelloExtensionsLen    State = 8
	ClientHelloExtensionsData   State = 9
	ClientHelloCompleted        State = 10

	SupportedVersions   ExtensionType = 43
	ExtTypeKeyShare            ExtensionType = 51
	SignatureAlgorithms ExtensionType = 13
	SupportedGroups ExtensionType = 10
)

type Extension struct {
	Type ExtensionType
	Data []byte
}

type KeyShareEntry struct {
    Group   uint16    // 0x001D = X25519, 0x0017 = secp256r1
    KeyExchange []byte    // public key 
}

type ClientHello struct {
	LegacyVersion     [2]byte
	Random            [32]byte
	LegacySessionID   []byte
	CipherSuites      []uint16
	LegacyCompression []byte
	Extensions        []Extension
	KeyShare	[]KeyShareEntry
    SignatureAlgorithms []uint16
	ClientHelloState  int

	sessionIDLen    uint8
	cipherSuitesLen uint16
	cipherSuitesRaw []byte
	compressionLen  uint8
	extensionsLen   uint16
	extensionsRaw   []byte
}

func parseKeyShareClientHello(ext *Extension) ([]KeyShareEntry, error) {
    data := ext.Data
    if len(data) < 2 {
        return nil, errors.New("key_share too short")
    }
    listLen := int(binary.BigEndian.Uint16(data[:2]))
    end := 2 + listLen
    if end > len(data) {
        return nil, errors.New("key_share list length exceeds data")
    }

    var entries []KeyShareEntry
    for i := 2; i < end; {
        if i+4 > end {
            return nil, errors.New("key_share entry header truncated")
        }
        group := binary.BigEndian.Uint16(data[i:])
        keyLen := int(binary.BigEndian.Uint16(data[i+2:]))
        i += 4
        if i+keyLen > end {
            return nil, errors.New("key_share key_exchange truncated")
        }
        keyExchange := make([]byte, keyLen)
        copy(keyExchange, data[i:i+keyLen])
        entries = append(entries, KeyShareEntry{Group: group, KeyExchange: keyExchange})
        i += keyLen
    }
    return entries, nil
}

func parseSupportedVersion(ext *Extension) bool {
	supportedVersion := []byte{0x03, 0x04}

	for i := 1; i < len(ext.Data); i += 2 {
		if bytes.Equal(ext.Data[i:i+2], supportedVersion) {
			return true
		}
	}

	return false
}

func (clientHello *ClientHello) parseExtensionsRaw() (int, error) {
	exts := make([]Extension, 0)
	for i := 0; i < len(clientHello.extensionsRaw); {
		extType := binary.BigEndian.Uint16(clientHello.extensionsRaw[i:])
		extLen := binary.BigEndian.Uint16(clientHello.extensionsRaw[i+2:])
		i += 4
		extData := make([]byte, extLen)
		copy(extData, clientHello.extensionsRaw[i:i+int(extLen)])

		newExt := Extension{Type: ExtensionType(extType), Data: extData}
		exts = append(exts, newExt)
		i += int(extLen)

		switch newExt.Type {
		case ExtTypeKeyShare:
			ks, err := parseKeyShareClientHello(&newExt)
			if err != nil {
				return int(clientHello.extensionsLen), err
			}
			clientHello.KeyShare = append(clientHello.KeyShare, ks...)
		case SupportedVersions:
			if !parseSupportedVersion(&newExt) {
				return int(clientHello.extensionsLen), errors.New("Version not suppported")
			}
		}
	}
	clientHello.Extensions = exts
	clientHello.ClientHelloState = int(ClientHelloCompleted)
	return 0, nil
}

func (clientHello *ClientHello) parseSingle(data []byte) (int, error) {
	switch State(clientHello.ClientHelloState) {

	case ClientHelloInitialized:
		if len(data) < 2 {
			return 0, errors.New("Not enough data to parse LegacyVersion")
		}
		copy(clientHello.LegacyVersion[:], data[:2])
		clientHello.ClientHelloState = int(ClientHelloVersionDone)
		return 2, nil

	case ClientHelloVersionDone:
		if len(data) < 32 {
			return 0, errors.New("Not enough data to parse Random")
		}
		copy(clientHello.Random[:], data[:32])
		clientHello.ClientHelloState = int(ClientHelloRandomDone)
		return 32, nil

	case ClientHelloRandomDone:
		if len(data) < 1 {
			return 0, errors.New("Not enough data to parse LegacySessionID length")
		}
		sessionIDLen := data[0]
		if sessionIDLen > 0 {
			clientHello.sessionIDLen = sessionIDLen
			clientHello.ClientHelloState = int(ClientHelloSessionIDData)
		} else {
			clientHello.LegacySessionID = []byte{}
			clientHello.ClientHelloState = int(ClientHelloCipherSuitesLen)
		}
		return 1, nil

	case ClientHelloSessionIDData:
		if len(data) < int(clientHello.sessionIDLen) {
			return 0, errors.New("Not enough data to parse LegacySessionID")
		}
		clientHello.LegacySessionID = make([]byte, clientHello.sessionIDLen)
		copy(clientHello.LegacySessionID, data[:clientHello.sessionIDLen])
		clientHello.ClientHelloState = int(ClientHelloCipherSuitesLen)
		return int(clientHello.sessionIDLen), nil

	case ClientHelloCipherSuitesLen:
		if len(data) < 2 {
			return 0, errors.New("Not enough data to parse CipherSuites length")
		}
		clientHello.cipherSuitesLen = binary.BigEndian.Uint16(data[:2])
		clientHello.ClientHelloState = int(ClientHelloCipherSuitesData)
		return 2, nil

	case ClientHelloCipherSuitesData:
		need := int(clientHello.cipherSuitesLen) - len(clientHello.cipherSuitesRaw)
		if len(data) < need {
			return 0, errors.New("Not enough data to parse CipherSuites")
		}
		clientHello.cipherSuitesRaw = append(clientHello.cipherSuitesRaw, data[:need]...)
		if len(clientHello.cipherSuitesRaw) == int(clientHello.cipherSuitesLen) {
			clientHello.CipherSuites = make([]uint16, clientHello.cipherSuitesLen/2)
			for i := range clientHello.CipherSuites {
				clientHello.CipherSuites[i] = binary.BigEndian.Uint16(clientHello.cipherSuitesRaw[i*2:])
			}
			clientHello.ClientHelloState = int(ClientHelloCompressionLen)
		}
		return need, nil

	case ClientHelloCompressionLen:
		if len(data) < 1 {
			return 0, errors.New("Not enough data to parse LegacyCompression length")
		}
		compressionLen := data[0]
		if compressionLen > 0 {
			clientHello.compressionLen = compressionLen
			clientHello.ClientHelloState = int(ClientHelloCompressionData)
		} else {
			clientHello.LegacyCompression = []byte{}
			clientHello.ClientHelloState = int(ClientHelloExtensionsLen)
		}
		return 1, nil

	case ClientHelloCompressionData:
		if len(data) < int(clientHello.compressionLen) {
			return 0, errors.New("Not enough data to parse LegacyCompression")
		}
		clientHello.LegacyCompression = make([]byte, clientHello.compressionLen)
		copy(clientHello.LegacyCompression, data[:clientHello.compressionLen])
		clientHello.ClientHelloState = int(ClientHelloExtensionsLen)
		return int(clientHello.compressionLen), nil

	case ClientHelloExtensionsLen:
		if len(data) < 2 {
			return 0, errors.New("Not enough data to parse Extensions length")
		}
		clientHello.extensionsLen = binary.BigEndian.Uint16(data[:2])
		clientHello.ClientHelloState = int(ClientHelloExtensionsData)
		return 2, nil

	case ClientHelloExtensionsData:
        need := int(clientHello.extensionsLen) - len(clientHello.extensionsRaw)
        if len(data) < need {
            return 0, errors.New("Not enough data to parse Extensions")
        }
        clientHello.extensionsRaw = append(clientHello.extensionsRaw, data[:need]...)

		// we have everything ready to parse extensions
        if len(clientHello.extensionsRaw) == int(clientHello.extensionsLen) {
            return clientHello.parseExtensionsRaw()
        }
	}

	return 0, nil
}

func (clientHello *ClientHello) Parse(data []byte) (int, error) {
	bytesParsed := 0
	for State(clientHello.ClientHelloState) != ClientHelloCompleted {
		n, err := clientHello.parseSingle(data[bytesParsed:])
		if err != nil {
			return bytesParsed, err
		}

		if n == 0 {
			return bytesParsed, nil
		}

		bytesParsed += n
	}

	return bytesParsed, nil
}
