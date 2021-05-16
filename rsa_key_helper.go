package rsa_textencryptor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const keyError = "invalid key: %v \n"

// ParsePrivateKey parse pem data to return a *rsa.PrivateKey
func ParsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf(keyError, "bad block type")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf(keyError, block.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(keyError, err)
	}

	return key, nil
}

// ParsePublicKey parse pem data to return a *rsa.PublicKey
func ParsePublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf(keyError, "bad block type")
	}

	if block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf(keyError, block.Type)
	}

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(keyError, err)
	}

	return key, nil
}

func generateKeyPair() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return key, nil
}
