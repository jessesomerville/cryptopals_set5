package socketclient

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
)

type Message struct {
	Type int
	Data []byte
}

func (m *Message) Serialize() ([]byte, error) {
	b := bytes.Buffer{}
	encoder := gob.NewEncoder(&b)
	if err := encoder.Encode(m); err != nil {
		return nil, fmt.Errorf("failed to serialize message: %v", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(b.Bytes())), nil
}

func DeserializeMessage(encoded []byte) (*Message, error) {
	rawBytes, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("failed to decode message bytes: %v", err)
	}

	messageBytes := bytes.Buffer{}
	messageBytes.Write(rawBytes)
	decoder := gob.NewDecoder(&messageBytes)

	m := Message{}
	if err := decoder.Decode(&m); err != nil {
		return nil, fmt.Errorf("failed to deserialize message: %v", err)
	}
	return &m, nil
}
