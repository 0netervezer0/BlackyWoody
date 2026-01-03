package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

const (
	saltSize  = 16
	nonceSize = 12
	keySize   = 32 // AES-256
)

type SecureConn struct {
	r   io.Reader
	w   io.Writer
	aead cipher.AEAD
}

func NewSecureConn(r io.Reader, w io.Writer, password string, isServer bool) (*SecureConn, error) {
	mySalt := make([]byte, saltSize)
	if _, err := rand.Read(mySalt); err != nil {
		return nil, err
	}

	peerSalt := make([]byte, saltSize)

	// Perform a symmetric salt exchange: write our salt, then read peer's salt.
	// Writing first on both sides avoids ordering issues where one side waits to read
	// while the other is also waiting to read.
	if _, err := w.Write(mySalt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, peerSalt); err != nil {
		return nil, err
	}

	var salt []byte
	if isServer {
		// serverSalt || clientSalt
		salt = append(mySalt, peerSalt...)
	} else {
		// serverSalt || clientSalt (peerSalt was read first on client)
		salt = append(peerSalt, mySalt...)
	}

	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, keySize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &SecureConn{r: r, w: w, aead: aead}, nil
}

func (c *SecureConn) WriteMessage(msg string) error {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := c.aead.Seal(nil, nonce, []byte(msg), nil)

	totalLen := uint32(len(nonce) + len(ciphertext))
	if err := binary.Write(c.w, binary.BigEndian, totalLen); err != nil {
		return err
	}

	if _, err := c.w.Write(nonce); err != nil {
		return err
	}
	_, err := c.w.Write(ciphertext)
	return err
}

func (c *SecureConn) ReadMessage() (string, error) {
	var totalLen uint32
	if err := binary.Read(c.r, binary.BigEndian, &totalLen); err != nil {
		return "", err
	}

	buf := make([]byte, totalLen)
	if _, err := io.ReadFull(c.r, buf); err != nil {
		return "", err
	}

	nonce := buf[:nonceSize]
	ciphertext := buf[nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed")
	}

	return string(plaintext), nil
}
