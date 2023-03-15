package main

import (
	"fmt"
	"log"
	"time"

	"github.com/jessesomerville/cryptopals_set5/color"
	dh "github.com/jessesomerville/cryptopals_set5/diffie_hellman"
	socketclient "github.com/jessesomerville/cryptopals_set5/socket_client"
)

// Incomplete
func challenge35() error {
	clientA, err := socketclient.NewDHSocketClient("ClientA")
	if err != nil {
		log.Fatal(err)
	}
	clientB, err := socketclient.NewDHSocketClient("ClientB")
	if err != nil {
		log.Fatal(err)
	}
	mitm, err := socketclient.NewMITMSocketClient("MITM")
	if err != nil {
		log.Fatal(err)
	}

	go mitm.Listen()    // Start MITM listener
	go clientA.Listen() // Start Peer listener

	fmt.Println("[+] Waiting 1 second to attempt to connect")
	time.Sleep(time.Second)

	// Have ClientB connect to ClientA through MITM
	if err := clientB.Connect(mitm.Port); err != nil {
		return err
	}
	defer clientB.Conn.Close()

	// Have ClientB initiate handshake with ClientA through MITM
	if err := clientB.DoHandshake(mitm.Port); err != nil {
		return err
	}

	// ClientA and ClientB compute their session keys
	clientA.SessionKey = dh.ComputeSessionKey(clientA.KeyPair, clientA.PeerPubKey)[:16]
	clientB.SessionKey = dh.ComputeSessionKey(clientB.KeyPair, clientB.PeerPubKey)[:16]

	fmt.Printf("[+] Finished handshake\n")

	color.Green("ClientA Key: %v", clientA.SessionKey)
	color.Green("ClientB Key: %v", clientB.SessionKey)

	msg := socketclient.Message{
		Type: 4,
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
