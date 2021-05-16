package rsa_textencryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

type RSASecretEncryptor struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}


type RSASecretEncryptorBuilder struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

//NewRSASecretEncryptorBuilder create a encryptor builder.  If a private key is set it will build a encryptor/decryptor.  If a
//public key is set it will build an encryptor.  If no key is set it will generate a random 2096 bit key for encryption decryption.
func NewRSASecretEncryptorBuilder() *RSASecretEncryptorBuilder {
	return &RSASecretEncryptorBuilder{}
}

//PublicKey specify a public key
func (b *RSASecretEncryptorBuilder) PublicKey(key *rsa.PublicKey) *RSASecretEncryptorBuilder {
	b.publicKey = key
	return b
}

//PrivateKey specify a private key
func (b *RSASecretEncryptorBuilder) PrivateKey(key *rsa.PrivateKey) *RSASecretEncryptorBuilder {
	b.privateKey = key
	return b
}

//Build If a private key is set it will build a encryptor/decryptor.  If a public key is set it will build an encryptor.
//If no key is set it will generate a random 2096 bit key for encryption decryption.
func (b *RSASecretEncryptorBuilder) Build() (*RSASecretEncryptor, error) {
	if b.publicKey == nil && b.privateKey == nil {
		key, err := generateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("unable to generate private key")
		}
		return &RSASecretEncryptor{
			privateKey: key,
			publicKey:  key.Public().(*rsa.PublicKey),
		}, nil
	}

	if b.privateKey != nil {
		return &RSASecretEncryptor{
			privateKey: b.privateKey,
			publicKey:  b.privateKey.Public().(*rsa.PublicKey),
		}, nil
	}

	return &RSASecretEncryptor{
		publicKey: b.publicKey,
	}, nil
}

//Encrypt encrypts a given string as RSA PKCS1v5 and returns a base64 representation.
func (r *RSASecretEncryptor) Encrypt(text string) (string, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, []byte(text))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

//Decrypt decrypts a base64 string into plain text.
func (r *RSASecretEncryptor) Decrypt(cipherText string) (string, error) {
	if !r.canDecrypt() {
		return "", fmt.Errorf("no private key configured")
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	length := readInt(cipherBytes) + 2
	random := cipherBytes[2:length]
	rawSecret, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, random)
	password := hex.EncodeToString(rawSecret)
	fmt.Println(password)
	fmt.Println(hex.EncodeToString(cipherBytes[length:]))
	fmt.Println(base64.StdEncoding.EncodeToString(cipherBytes[length:]))
	if err != nil {
		return "", err
	}

	result, _ := decrypt(password, cipherBytes[length:])

	return string(result), nil
}

func decrypt(password string, ciphertext []byte) ([]byte, error) {
	springKey := deriveSpringKey(password)
	block, err := aes.NewCipher(springKey)
	if err != nil {
		return []byte{}, err
	}

	if len(ciphertext) < aes.BlockSize {
		return []byte{}, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return []byte{}, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return PKCS5UnPadding(ciphertext), nil
}

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	padding := int(src[length-1])
	return src[:(length - padding)]
}

func (r *RSASecretEncryptor) canDecrypt() bool {
	if r.privateKey == nil {
		return false
	}
	return true
}

func readInt(b []byte) uint16 {
	return uint16(b[0] & 0xFF) << 8 |uint16(b[1] & 0xFF)
}

func writeInt(length int) []byte {
	data := make([]byte, 2);
	data[0] = (byte) ((length >> 8) & 0xFF)
	data[1] = (byte) (length & 0xFF)
	return data
}

func deriveSpringKey(passphrase string) []byte {
	salt, _ := hex.DecodeString("deadbeef")
	return pbkdf2.Key([]byte(passphrase),salt, 1024, 256, sha1.New)[:32]
}