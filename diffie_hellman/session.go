package dh

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"
)

// ComputeSessionKey generates a Diffie-Hellman session key from the client
// private key, the peer publicKey, and the Diffie-Hellman prime.
func ComputeSessionKey(clientKeyPair *DHKeyPair, peerPubKey *big.Int) []byte {
	sessionKey := new(big.Int).Exp(peerPubKey, clientKeyPair.privKey, clientKeyPair.Group.P)

	blen := (clientKeyPair.Group.P.BitLen() + 7) / 8
	paddedSessionKey := make([]byte, blen)
	copyWithLeftPad(paddedSessionKey, sessionKey.Bytes())

	hash := sha1.New()
	io.WriteString(hash, string(paddedSessionKey))
	return hash.Sum(nil)
}

// SerializeDHGroup serializes a Diffie-Hellman group
func SerializeDHGroup(grp *DHGroup) ([]byte, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	if err := e.Encode(grp); err != nil {
		return nil, fmt.Errorf("failed to serialize Diffie-Hellman Group: %w", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(b.Bytes())), nil
}

// DeserializeDHGroup deserializes a Diffie-Hellman group
func DeserializeDHGroup(encoded []byte) (*DHGroup, error) {
	rawBytes, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("failed to decode Diffie-Hellman Group bytes: %v", err)
	}

	groupBytes := bytes.Buffer{}
	groupBytes.Write(rawBytes)
	decoder := gob.NewDecoder(&groupBytes)

	groupMsg := DHGroup{}
	if err := decoder.Decode(&groupMsg); err != nil {
		return nil, fmt.Errorf("failed to deserialize handshake message: %v", err)
	}
	return &groupMsg, nil
}

// copyWithLeftPad copies src to the end of dest, padding with zero bytes.
func copyWithLeftPad(dest, src []byte) {
	padLen := len(dest) - len(src)
	for i := 0; i < padLen; i++ {
		dest[i] = 0
	}
	copy(dest[padLen:], src)
}
