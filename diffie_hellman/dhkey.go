package dh

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// DHKeyPair holds a public and private key pair and the associated Diffie-Hellman group
type DHKeyPair struct {
	privKey *big.Int
	PubKey  *big.Int

	group *DHGroup
}

// GenerateKeyPair creates a random private key in (0, p) and generates the
// associates public key.
func GenerateKeyPair(group *DHGroup) (*DHKeyPair, error) {
	privKey, err := rand.Int(rand.Reader, group.P)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	zero := big.NewInt(0)
	for privKey.Cmp(zero) == 0 {
		privKey, err = rand.Int(rand.Reader, group.P)
		if err != nil {
			return nil, fmt.Errorf("failed to regenerate random int: %v", err)
		}
	}

	key := &DHKeyPair{}
	key.privKey = privKey

	// pubKey = g ^ privKey mod p
	key.PubKey = new(big.Int).Exp(group.G, privKey, group.P)
	key.group = group
	return key, nil
}
