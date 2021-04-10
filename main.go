package main

import (
	"fmt"

	dh "github.com/jessesomerville/cryptopals_set5/diffie_hellman"
)

func main() {
	fmt.Printf("Shared Key: %x\n", challenge33())
}

func challenge33() []byte {
	group := dh.GetGroup()

	privA, err := group.GeneratePrivateKey(nil)
	if err != nil {
		panic(err)
	}

	privB, err := group.GeneratePrivateKey(nil)
	if err != nil {
		panic(err)
	}
	pubB := dh.NewPublicKey(privB.Bytes())

	key, err := group.ComputeKey(pubB, privA)
	if err != nil {
		panic(err)
	}
	return key.Bytes()
}
