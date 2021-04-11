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
	sessionKey := new(big.Int).Exp(peerPubKey, clientKeyPair.privKey, clientKeyPair.group.P)

	blen := (clientKeyPair.group.P.BitLen() + 7) / 8
	paddedSessionKey := make([]byte, blen)
	copyWithLeftPad(paddedSessionKey, sessionKey.Bytes())

	hash := sha1.New()
	io.WriteString(hash, string(paddedSessionKey))
	return hash.Sum(nil)
}

// SerializeDHParams serializes the client's DHKeyPair without the private key
func SerializeDHParams(clientKeyPair *DHKeyPair) ([]byte, error) {
	// Ensure we don't serialize the priv key
	scrubbedKey := DHKeyPair{}
	scrubbedKey.PubKey = clientKeyPair.PubKey
	scrubbedKey.group = clientKeyPair.group

	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	if err := e.Encode(scrubbedKey); err != nil {
		return nil, fmt.Errorf("failed to serialize handshake message: %v", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(b.Bytes())), nil
}

// DeserializeDHParams deserializes the peer's DHKeyPair
func DeserializeDHParams(encoded []byte) (*DHKeyPair, error) {
	rawBytes, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("failed to decode handshake bytes: %v", err)
	}

	handshakeBytes := bytes.Buffer{}
	handshakeBytes.Write(rawBytes)
	decoder := gob.NewDecoder(&handshakeBytes)

	handshakeMsg := DHKeyPair{}
	if err := decoder.Decode(&handshakeMsg); err != nil {
		return nil, fmt.Errorf("failed to deserialize handshake message: %v", err)
	}
	return &handshakeMsg, nil
}

// copyWithLeftPad copies src to the end of dest, padding with zero bytes.
func copyWithLeftPad(dest, src []byte) {
	padLen := len(dest) - len(src)
	for i := 0; i < padLen; i++ {
		dest[i] = 0
	}
	copy(dest[padLen:], src)
}
