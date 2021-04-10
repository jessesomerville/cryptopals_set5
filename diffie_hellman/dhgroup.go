package dh

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

type DHGroup struct {
	p *big.Int
	g *big.Int
}

func (group *DHGroup) P() *big.Int {
	p := new(big.Int)
	p.Set(group.p)
	return p
}

func (group *DHGroup) G() *big.Int {
	g := new(big.Int)
	g.Set(group.g)
	return g
}

func (group *DHGroup) GeneratePrivateKey(randReader io.Reader) (*DHKey, error) {
	if randReader == nil {
		randReader = rand.Reader
	}

	// x should be in (0, p).
	// alternative approach:
	// x, err := big.Add(rand.Int(randReader, big.Sub(p, big.NewInt(1))), big.NewInt(1))
	//
	// However, since x is highly unlikely to be zero if p is big enough,
	// we would rather use an iterative approach below,
	// which is more efficient in terms of expected running time.
	x, err := rand.Int(randReader, group.p)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random int: %v", err)
	}

	zero := big.NewInt(0)
	for x.Cmp(zero) == 0 {
		x, err = rand.Int(randReader, group.p)
		if err != nil {
			return nil, fmt.Errorf("failed to regenerate random int: %v", err)
		}
	}
	key := &DHKey{}
	key.privKey = x

	// y = g ^ x mod p
	key.pubKey = new(big.Int).Exp(group.g, x, group.p)
	key.group = group
	return key, nil
}

func (group *DHGroup) ComputeKey(pubkey *DHKey, privkey *DHKey) (*DHKey, error) {
	if group.p == nil {
		return nil, errors.New("DH: invalid group")
	}
	if pubkey.pubKey == nil {
		return nil, errors.New("DH: invalid public key")
	}
	if pubkey.pubKey.Sign() <= 0 || pubkey.pubKey.Cmp(group.p) >= 0 {
		return nil, errors.New("DH parameter out of bounds")
	}
	if privkey.privKey == nil {
		return nil, errors.New("DH: invalid private key")
	}

	k := new(big.Int).Exp(pubkey.pubKey, privkey.privKey, group.p)
	key := &DHKey{}
	key.pubKey = k
	key.group = group
	return key, nil
}

func GetGroup() *DHGroup {
	p, _ := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	return &DHGroup{
		p: p,
		g: new(big.Int).SetInt64(2),
	}
}
