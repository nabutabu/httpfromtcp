package tls13

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
)

type CurveID uint16

const (
	X25519 CurveID = 0x001D
	P256   CurveID = 0x0017
)

func curveForID(id CurveID) (ecdh.Curve, error) {
	switch id {
	case X25519:
		return ecdh.X25519(), nil
	case P256:
		return ecdh.P256(), nil
	default:
		return nil, errors.New("unsupported curve")
	}
}

func GenerateKeyShare(curveID CurveID) (privateKey []byte, publicKey []byte, err error) {
	curve, err := curveForID(curveID)
	if err != nil {
		return nil, nil, err
	}
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

func ComputeSharedSecret(privateKey, peerPublic []byte, curveID CurveID) ([]byte, error) {
	curve, err := curveForID(curveID)
	if err != nil {
		return nil, err
	}
	priv, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pub, err := curve.NewPublicKey(peerPublic)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

func UnmarshalPublicKey(data []byte, curveID CurveID) ([]byte, error) {
	curve, err := curveForID(curveID)
	if err != nil {
		return nil, err
	}
	_, err = curve.NewPublicKey(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}