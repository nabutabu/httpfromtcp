package handshake

import (
	"encoding/binary"
	"errors"
)

type HandshakeType byte
type State int

const (
	client_hello         HandshakeType = HandshakeType(1)
	server_hello         HandshakeType = HandshakeType(2)
	new_session_ticket   HandshakeType = HandshakeType(4)
	end_of_early_data    HandshakeType = HandshakeType(5)
	encrypted_extensions HandshakeType = HandshakeType(8)
	certificate          HandshakeType = HandshakeType(11)
	certificate_request  HandshakeType = HandshakeType(13)
	certificate_verify   HandshakeType = HandshakeType(15)
	finished             HandshakeType = HandshakeType(20)
	key_update           HandshakeType = HandshakeType(24)
	message_hash         HandshakeType = HandshakeType(254)

	HandshakeInitialized State = 1
	HandshakeMsgTypeDone State = 2
	HandshakeLengthDone  State = 3
	HandshakeComplete    State = 4
)

type Handshake struct {
	msg_type       HandshakeType
	length         uint16 // why is this uint24 in the spec, what is the golang equivalent
	msg            []byte
	HandshakeState State
}

func (hs *Handshake) parseSingle(data []byte) (int, error) {
	switch hs.HandshakeState {

	case HandshakeInitialized:
		// parse HandshakeType
		if len(data) < 1 {
			return 0, errors.New("Not enough data to parse HandshakeType")
		}

		hsType := HandshakeType(data[0])

		switch hsType {
		case client_hello, server_hello, new_session_ticket, end_of_early_data,
			encrypted_extensions, certificate, certificate_request, certificate_verify,
			finished, key_update, message_hash:
		default:
			return 0, errors.New("Invalid HandshakeType")
		}

		hs.msg_type = hsType
		hs.HandshakeState = HandshakeMsgTypeDone

		return 1, nil
	case HandshakeMsgTypeDone:
		// parse length
		if len(data) < 2 {
			return 0, errors.New("Not enough data to parse length")
		}

		size := binary.BigEndian.Uint16(data[0:2])

		hs.length = size
		hs.HandshakeState = HandshakeLengthDone
		return 2, nil
	case HandshakeLengthDone:
		// parse fragment contents
		if len(data)+len(hs.msg) > int(hs.length) {
			return 0, errors.New("Size of data is greater than specified length")
		}

		hs.msg = append(hs.msg, data...)

		if len(hs.msg) == int(hs.length) {
			hs.HandshakeState = HandshakeComplete
			return len(data), nil
		}

		return len(data), nil
	}
	return 0, nil
}

func (hs *Handshake) Parse(data []byte) (int, error) {
	// because our current chunk can have multiple parts of the request
	// (both request line and headers for ex)
	// run the loop until either the entire request is parsed or all bytes are consumed
	bytesParsed := 0
	for hs.HandshakeState != HandshakeComplete {
		n, err := hs.parseSingle(data[bytesParsed:])
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
