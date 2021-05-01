package socketclient

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/fatih/color"
	aescbc "github.com/jessesomerville/cryptopals_set5/aes"
	dh "github.com/jessesomerville/cryptopals_set5/diffie_hellman"
)

// DHSocketClient handles socket connections on localhost and can perform DH
// key negotiations.
type DHSocketClient struct {
	ID   string
	Port int

	Conn     net.Conn
	Listener net.Listener

	KeyPair    *dh.DHKeyPair
	PeerPubKey *big.Int
	SessionKey []byte
}

func NewDHSocketClient(id string) (*DHSocketClient, error) {
	client := DHSocketClient{}

	port, err := getFreePort()
	if err != nil {
		return nil, fmt.Errorf("set port: %v", err)
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

func (client *DHSocketClient) Listen() (err error) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", client.Port))
	if err != nil {
		return fmt.Errorf("%s - start client listener: %v", client.ID, err)
	}
	defer l.Close()
	client.Listener = l

	for {
		conn, err := client.Listener.Accept()
		if err != nil {
			return fmt.Errorf("%s - accept connection: %v", client.ID, err)
		}

		go client.handleConnection(conn)
	}
}

func (client *DHSocketClient) handleConnection(conn net.Conn) {
	msg, err := client.ReadMessage(conn)
	if err != nil {
		log.Fatal(err)
	}

	respMsg := Message{}
	switch msg.Type {
	case 0:
		peerKeyPair, err := dh.DeserializeDHParams(msg.Data)
		if err != nil {
			log.Fatal(err)
		}
		client.PeerPubKey = peerKeyPair.PubKey

		respMsg = Message{
			Type: 1,
			Data: client.KeyPair.PubKey.Bytes(),
		}
	case 2:
		color.Blue("[+] %s recieved: %s", client.ID, string(msg.Data))

		respMsg = Message{
			Type: 2,
			Data: []byte("World"),
		}
	default:
		log.Fatalf("%s recieved unknown message type: %d", client.ID, msg.Type)
	}
	client.SendMessage(conn, respMsg)
	client.handleConnection(conn)
}

func (client *DHSocketClient) Connect(port int) error {
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

func (client *DHSocketClient) DoHandshake(peerPort int) error {
	clientKeyData, err := dh.SerializeDHParams(client.KeyPair)
	if err != nil {
		return err
	}

	initMsg := Message{Type: 0, Data: clientKeyData}
	if err := client.SendMessage(client.Conn, initMsg); err != nil {
		return err
	}
	respMsg, err := client.ReadMessage(client.Conn)
	if err != nil {
		return err
	}

	if respMsg.Type != 1 {
		return fmt.Errorf("%s - peer replied to message type 0 with message type %d", client.ID, respMsg.Type)
	}
	peerPubKey := big.Int{}
	peerPubKey.SetBytes(respMsg.Data)
	client.PeerPubKey = &peerPubKey
	return nil
}

func (client *DHSocketClient) ReadMessage(conn net.Conn) (*Message, error) {
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

func (client *DHSocketClient) SendMessage(conn net.Conn, msg Message) error {
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

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, fmt.Errorf("failed to resolve tcp://localhost:0: %v", err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("failed to start tcp listener: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
