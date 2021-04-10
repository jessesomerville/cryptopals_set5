package dh

import "math/big"

type DHKey struct {
	privKey *big.Int
	pubKey  *big.Int

	group *DHGroup
}

func (key *DHKey) Bytes() []byte {
	if key.pubKey == nil {
		return nil
	}
	if key.group != nil {
		blen := (key.group.p.BitLen() + 7) / 8
		pubKeyBytes := make([]byte, blen)
		copyWithLeftPad(pubKeyBytes, key.pubKey.Bytes())
		return pubKeyBytes
	}
	return key.pubKey.Bytes()
}

func (key *DHKey) String() string {
	if key.pubKey == nil {
		return ""
	}
	return key.pubKey.String()
}

func (key *DHKey) IsPrivateKey() bool {
	return key.privKey != nil
}

func NewPublicKey(s []byte) *DHKey {
	key := new(DHKey)
	key.pubKey = new(big.Int).SetBytes(s)
	return key
}

// copyWithLeftPad copies src to the end of dest, padding with zero bytes.
func copyWithLeftPad(dest, src []byte) {
	padLen := len(dest) - len(src)
	for i := 0; i < padLen; i++ {
		dest[i] = 0
	}
	copy(dest[padLen:], src)
}
