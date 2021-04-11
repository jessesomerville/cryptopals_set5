package aescbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func Encrypt(pt, key []byte) ([]byte, error) {
	padded := pkcs5(pt, aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, aes.BlockSize+len(padded))
	iv := ct[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct[aes.BlockSize:], padded)
	return ct, nil
}

func Decrypt(ct, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ct) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext of length %d is too short", len(ct))
	}
	iv := ct[:aes.BlockSize]
	ct = ct[aes.BlockSize:]

	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext of length %d is not multiple of block size", len(ct))
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ct, ct)
	return removePadding(ct), nil
}

func pkcs5(data []byte, blocksize int) []byte {
	padByte := (blocksize - len(data)%blocksize)
	if padByte == 0 {
		padByte = 16
	}
	padding := bytes.Repeat([]byte{byte(padByte)}, padByte)
	return append(data, padding...)
}

func removePadding(data []byte) []byte {
	padByte := data[len(data)-1]
	return data[:len(data)-int(padByte)]
}
