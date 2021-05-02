package main

import dh "github.com/jessesomerville/cryptopals_set5/diffie_hellman"

func challenge33() []byte {
	group := dh.GetGroup()

	keypairA, err := dh.GenerateKeyPair(group)
	if err != nil {
		panic(err)
	}

	keypairB, err := dh.GenerateKeyPair(group)
	if err != nil {
		panic(err)
	}

	return dh.ComputeSessionKey(keypairA, keypairB.PubKey)
}
