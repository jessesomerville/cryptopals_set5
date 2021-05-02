package socketclient

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/fatih/color"
	aescbc "github.com/jessesomerville/cryptopals_set5/aes"
	dh "github.com/jessesomerville/cryptopals_set5/diffie_hellman"
)

type MITMSocketClient struct {
	ID   string
	Port int

	Conn     net.Conn
	Listener net.Listener

	KeyPair     *dh.DHKeyPair
	PeerDHGroup *dh.DHGroup

	ClientAPubKey *big.Int
	ClientBPubKey *big.Int
	SessionKey    []byte
}

func NewMITMSocketClient(id string) (*MITMSocketClient, error) {
	client := MITMSocketClient{}

	port, err := getFreePort()
	if err != nil {
		return nil, fmt.Errorf("set port: %w", err)
	}
	client.Port = port

	keyPair, err := dh.GenerateKeyPair(dh.GetGroup())
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair for socket client: %v", err)
	}
	client.KeyPair = keyPair

	client.ID = id
	return &client, nil
}

func (client *MITMSocketClient) Listen() (err error) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", client.Port))
	if err != nil {
		return fmt.Errorf("%s - start MITM client listener: %v", client.ID, err)
	}
	defer l.Close()
	client.Listener = l

	for {
		conn, err := client.Listener.Accept()
		if err != nil {
			return fmt.Errorf("%s - MITM accept connection: %v", client.ID, err)
		}

		go client.handleConnection(conn)
	}
}

func (client *MITMSocketClient) handleConnection(conn net.Conn) {
	msg, err := client.ReadMessage(conn)
	if err != nil {
		log.Fatal(err)
	}

	respMsg := Message{}
	switch msg.Type {
	case 0: // Client initiates handshake and sends DHGroup (p, g)
		respMsg = *client.HandleHandshakeInit(msg)
	case 2: // Client sends public key
		respMsg = *client.HandleHandshakePubkey(msg)
	case 4: // Normal message after handshake
		respMsg = *client.HandleNormalMessage(msg)
	default:
		log.Fatalf("%s recieved unknown message type: %d", client.ID, msg.Type)
	}
	client.SendMessage(conn, respMsg)
	client.handleConnection(conn)
}

func (client *MITMSocketClient) HandleHandshakeInit(msg *Message) *Message {
	color.Red("[+] MITM recieved handshake initiation")
	clientAGroup, err := dh.DeserializeDHGroup(msg.Data)
	if err != nil {
		log.Fatal(err)
	}
	client.PeerDHGroup = clientAGroup

	forwardMsgData, err := dh.SerializeDHGroup(clientAGroup)
	if err != nil {
		color.Red("[!] MITM failed to serialize injected DH Group")
		os.Exit(1)
	}
	forwardMsg := Message{
		Type: 0,
		Data: forwardMsgData,
	}

	if err := client.SendMessage(client.Conn, forwardMsg); err != nil {
		color.Red("[!] MITM failed to forward handshake message")
		os.Exit(1)
	}
	respMsg, err := client.ReadMessage(client.Conn)
	if err != nil {
		color.Red("[!] MITM failed to read handshake response")
		os.Exit(1)
	}

	color.Red("[+] MITM returning p to handshake initiator")
	return respMsg
}

func (client *MITMSocketClient) HandleHandshakePubkey(msg *Message) *Message {
	clientAPubKey := big.Int{}
	clientAPubKey.SetBytes(msg.Data)
	client.ClientAPubKey = &clientAPubKey

	if err := client.SendMessage(client.Conn, *msg); err != nil {
		color.Red("[!] MITM failed to forward pubkey message")
		os.Exit(1)
	}
	respMsg, err := client.ReadMessage(client.Conn)
	if err != nil {
		color.Red("[!] MITM failed to read pubkey response")
		os.Exit(1)
	}
	clientBPubKey := big.Int{}
	clientBPubKey.SetBytes(msg.Data)
	client.ClientBPubKey = &clientBPubKey
	return respMsg
}

func (client *MITMSocketClient) HandleNormalMessage(msg *Message) *Message {
	color.Red("[+] %s recieved: %s", client.ID, string(msg.Data))
	if err := client.SendMessage(client.Conn, *msg); err != nil {
		color.Red("[!] MITM failed to forward normal message")
		os.Exit(1)
	}
	respMsg, err := client.ReadMessage(client.Conn)
	if err != nil {
		color.Red("[!] MITM failed to read handshake response")
		os.Exit(1)
	}
	color.Red("[+] %s recieved: %s", client.ID, string(respMsg.Data))
	return respMsg
}

func (client *MITMSocketClient) Connect(port int) error {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return fmt.Errorf("%s - client connect: %v", client.ID, err)
	}
	client.Conn = conn
	return nil
}

func (client *MITMSocketClient) ReadMessage(conn net.Conn) (*Message, error) {
	resp := make([]byte, 4096)
	readLen, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("%s - read message: %v", client.ID, err)
	}
	respBytes := resp[:readLen]

	if client.SessionKey != nil {
		respBytes, err = aescbc.Decrypt(respBytes, client.SessionKey)
		if err != nil {
			return nil, err
		}
	}

	msg, err := DeserializeMessage(respBytes)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (client *MITMSocketClient) SendMessage(conn net.Conn, msg Message) error {
	msgData, err := msg.Serialize()
	if err != nil {
		return err
	}

	if client.SessionKey != nil {
		msgData, err = aescbc.Encrypt(msgData, client.SessionKey)
		if err != nil {
			return err
		}
	}

	if _, err := conn.Write(msgData); err != nil {
		return fmt.Errorf("%s - send message: %v", client.ID, err)
	}
	return nil
}
