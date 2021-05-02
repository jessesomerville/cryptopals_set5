package rsa

import (
	"crypto/rand"
	"math/big"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

func RandPrime() (*big.Int, error) {
	return rand.Prime(rand.Reader, 1024)
}

// func Invmod(e, et *big.Int) *big.Int {
// 	return new(big.Int).ModInverse(e, et)
// }

func Encrypt(m, e, n *big.Int) *big.Int {
	return new(big.Int).Exp(m, e, n)
}

func Decrypt(c, d, n *big.Int) *big.Int {
	return new(big.Int).Exp(c, d, n)
}

func eGCD(a, b *big.Int) (gcd, prevS, prevT *big.Int) {
	// Ref:
	// http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm

	r := big.NewInt(1) // anything but 0, to start the loop
	gcd = new(big.Int).Set(a)
	prevQ := new(big.Int).Set(b)
	// S0 == 1, S1 == 0
	// T0 == 0, T1 == 1
	s := new(big.Int)
	t := big.NewInt(1)
	prevS = big.NewInt(1)
	prevT = new(big.Int)
	// scratch var
	saved := new(big.Int)

	for r.Sign() != 0 {
		gcd, r := gcd.QuoRem(gcd, prevQ, r)

		saved.Set(s)
		s.Mul(gcd, s)
		s.Sub(prevS, s)
		prevS.Set(saved)

		saved.Set(t)
		t.Mul(gcd, t)
		t.Sub(prevT, t)
		prevT.Set(saved)

		gcd.Set(prevQ)
		prevQ.Set(r)

	}

	return
}

func InvMod(e, et *big.Int) *big.Int {
	_, s, _ := eGCD(e, et)
	if s.Sign() == -1 {
		s.Add(s, et)
	}
	return s
}
