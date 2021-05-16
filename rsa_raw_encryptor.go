package rsa_textencryptor

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
)

type RSARawEncryptor struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

type RSARawEncryptorBuilder struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

//NewRSARawEncryptorBuilder create a encryptor builder.  If a private key is set it will build a encryptor/decryptor.  If a
//public key is set it will build an encryptor.  If no key is set it will generate a random 2096 bit key for encryption decryption.
func NewRSARawEncryptorBuilder() *RSARawEncryptorBuilder {
	return &RSARawEncryptorBuilder{}
}

//PublicKey specify a public key
func (b *RSARawEncryptorBuilder) PublicKey(key *rsa.PublicKey) *RSARawEncryptorBuilder {
	b.publicKey = key
	return b
}

//PrivateKey specify a private key
func (b *RSARawEncryptorBuilder) PrivateKey(key *rsa.PrivateKey) *RSARawEncryptorBuilder {
	b.privateKey = key
	return b
}

//Build If a private key is set it will build a encryptor/decryptor.  If a public key is set it will build an encryptor.
//If no key is set it will generate a random 2096 bit key for encryption decryption.
func (b *RSARawEncryptorBuilder) Build() (*RSARawEncryptor, error) {
	if b.publicKey == nil && b.privateKey == nil {
		key, err := generateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("unable to generate private key")
		}
		return &RSARawEncryptor{
			privateKey: key,
			publicKey:  key.Public().(*rsa.PublicKey),
		}, nil
	}

	if b.privateKey != nil {
		return &RSARawEncryptor{
			privateKey: b.privateKey,
			publicKey:  b.privateKey.Public().(*rsa.PublicKey),
		}, nil
	}

	return &RSARawEncryptor{
		publicKey: b.publicKey,
	}, nil
}

//Encrypt encrypts a given string as RSA PKCS1v5 and returns a base64 representation.
func (r *RSARawEncryptor) Encrypt(text string) (string, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, []byte(text))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

//Decrypt decrypts a base64 string into plain text.
func (r *RSARawEncryptor) Decrypt(cipher string) (string, error) {
	if !r.canDecrypt() {
		return "", fmt.Errorf("no private key configured")
	}
	secret, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		return "", err
	}
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, secret)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (r *RSARawEncryptor) canDecrypt() bool {
	if r.privateKey == nil {
		return false
	}
	return true
}
