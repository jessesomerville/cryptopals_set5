package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/jessesomerville/cryptopals_set5/rsa"
)

var one = big.NewInt(1)

func challenge39() {
	p, err := rsa.RandPrime()
	if err != nil {
		log.Fatal(err)
	}

	q, err := rsa.RandPrime()
	if err != nil {
		log.Fatal(err)
	}

	n := new(big.Int)
	n.Mul(p, q)

	et := new(big.Int)
	et.Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))

	e := big.NewInt(3)

	d := rsa.InvMod(e, et)

	msg := big.NewInt(42)
	ct := rsa.Encrypt(msg, e, n)

	fmt.Printf("Ciphertext: %d\n", ct)

	pt := rsa.Decrypt(ct, d, n)

	fmt.Printf("Plaintext: %d", pt)
}
