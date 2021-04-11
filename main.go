package main

import (
	"fmt"
	"log"
	"time"

	dh "github.com/jessesomerville/cryptopals_set5/diffie_hellman"
	socketclient "github.com/jessesomerville/cryptopals_set5/socket_client"
)

func main() {
	// fmt.Printf("Shared Key: %x\n", challenge33())
	if err := challenge34(); err != nil {
		log.Fatal(err)
	}
}

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

func challenge34() error {
	clientA, err := socketclient.NewDHSocketClient("ClientA")
	if err != nil {
		log.Fatal(err)
	}
	clientB, err := socketclient.NewDHSocketClient("ClientB")
	if err != nil {
		log.Fatal(err)
	}

	go clientA.Listen()
	fmt.Println("[+] Waiting 1 second to attempt to connect")
	time.Sleep(time.Second)

	if err := clientB.Connect(clientA.Port); err != nil {
		return err
	}
	defer clientB.Conn.Close()

	if err := clientB.DoHandshake(clientA.Port); err != nil {
		return err
	}

	clientA.SessionKey = dh.ComputeSessionKey(clientA.KeyPair, clientA.PeerPubKey)[:16]
	clientB.SessionKey = dh.ComputeSessionKey(clientB.KeyPair, clientB.PeerPubKey)[:16]

	fmt.Printf("[+] Finished handshake\n")

	msg := socketclient.Message{
		Type: 2,
		Data: []byte("Hello"),
	}
	if err := clientB.SendMessage(clientB.Conn, msg); err != nil {
		return err
	}

	respMsg, err := clientB.ReadMessage(clientB.Conn)
	if err != nil {
		return err
	}
	fmt.Printf("[+] %s received: %v\n\n", clientB.ID, respMsg.Data)

	exitMsg := socketclient.Message{
		Type: 99,
		Data: []byte{},
	}
	if err := clientB.SendMessage(clientB.Conn, exitMsg); err != nil {
		return err
	}

	return nil
}
