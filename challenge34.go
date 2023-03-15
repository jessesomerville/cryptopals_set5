package main

import (
	"fmt"
	"log"
	"time"

	"github.com/jessesomerville/cryptopals_set5/color"
	dh "github.com/jessesomerville/cryptopals_set5/diffie_hellman"
	socketclient "github.com/jessesomerville/cryptopals_set5/socket_client"
)

func challenge34() error {
	clientA, err := socketclient.NewDHSocketClient("ClientA")
	if err != nil {
		log.Fatal(err)
	}
	clientB, err := socketclient.NewDHSocketClient("ClientB")
	if err != nil {
		log.Fatal(err)
	}
	MITM, err := socketclient.NewMITMSocketClient("MITM")
	if err != nil {
		log.Fatal(err)
	}

	go MITM.Listen()    // Start MITM listener
	go clientA.Listen() // Start Peer listener

	fmt.Println("[+] Waiting 1 second to attempt to connect")
	time.Sleep(time.Second)

	// Have ClientB connect to the MITM
	if err := clientB.Connect(MITM.Port); err != nil {
		return err
	}
	defer clientB.Conn.Close()

	// Have the MITM connect to ClientA
	if err := MITM.Connect(clientA.Port); err != nil {
		return err
	}
	defer MITM.Conn.Close()

	// Have ClientB initiate handshake with ClientA through the MITM
	if err := clientB.DoHandshake(MITM.Port); err != nil {
		return err
	}

	// ClientA and ClientB compute their session keys with what they think is the other's public key
	clientA.SessionKey = dh.ComputeSessionKey(clientA.KeyPair, clientA.PeerPubKey)[:16]
	clientB.SessionKey = dh.ComputeSessionKey(clientB.KeyPair, clientB.PeerPubKey)[:16]

	// The MITM computes the same session key using the prime from the DHGroup the others used
	MITM.SessionKey = dh.ComputeSessionKey(MITM.KeyPair, MITM.PeerDHGroup.P)[:16]

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
	color.Blue("[+] %s received: %s\n\n", clientB.ID, string(respMsg.Data))

	exitMsg := socketclient.Message{
		Type: 99,
		Data: []byte{},
	}
	if err := clientB.SendMessage(clientB.Conn, exitMsg); err != nil {
		return err
	}

	return nil
}
