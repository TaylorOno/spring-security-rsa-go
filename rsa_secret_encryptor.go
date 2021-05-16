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
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const _AESSecretSize = 16

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

//Encrypt takes a plainText string and will generate a random 16 byte password.  That is used to AES encrypt the secret.
//the password will then be RSA encrypted an prepended to the cipher text which is returned as a base64 encoded string.
func (r *RSASecretEncryptor) Encrypt(plainText string) (string, error) {
	random := make([]byte, _AESSecretSize)
	rand.Reader.Read(random)

	secret, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, random)
	if err != nil {
		return "", err
	}

	cipher, err := encryptAES(hex.EncodeToString(random), []byte(plainText))
	cipherBytes := bytes.Buffer{}

	//cipherBytes[0:2] bytes used to store encrypted password length
	cipherBytes.Write(writeInt(len(secret)))

	//cipherBytes[2:length] RSA encrypted AES password
	cipherBytes.Write(secret)

	//cipherBytes[length:] AES encrypted bytes
	cipherBytes.Write(cipher)
	return base64.StdEncoding.EncodeToString(cipherBytes.Bytes()), nil
}

func encryptAES(password string, plaintext []byte) ([]byte, error) {
	plaintext = PKCS5Padding(plaintext, aes.BlockSize)

	springKey := deriveSpringKey(password)
	fmt.Printf("springKey Encrypt:%v\n", hex.EncodeToString(springKey))
	block, err := aes.NewCipher(springKey)
	if err != nil {
		return []byte{}, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

//Decrypt a base64 encoded cipherText string by first decrypting the aes password prefix.  Then uses the decrypted
//password to decrypt the AES encrypted payload returning a plaintext string.
func (r *RSASecretEncryptor) Decrypt(cipherText string) (string, error) {
	if !r.canDecrypt() {
		return "", fmt.Errorf("no private key configured")
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	//cipherBytes[0:2] bytes used to store encrypted password length
	length := readInt(cipherBytes) + 2

	//cipherBytes[2:length] RSA encrypted AES password
	random := cipherBytes[2:length]
	rawSecret, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, random)
	if err != nil {
		return "", err
	}

	//cipherBytes[length:] AES encrypted bytes
	result, err := decryptAES(hex.EncodeToString(rawSecret), cipherBytes[length:])
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func decryptAES(password string, ciphertext []byte) ([]byte, error) {
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

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
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
	return uint16(b[0]&0xFF)<<8 | uint16(b[1]&0xFF)
}

func writeInt(length int) []byte {
	data := make([]byte, 2)
	data[0] = (byte)((length >> 8) & 0xFF)
	data[1] = (byte)(length & 0xFF)
	return data
}

//deriveSpringKey generates an AES key from a passphrase mimicking the java AES key generation found in
//org.springframework.security.crypto.encrypt.AesBytesEncryptor.java
func deriveSpringKey(passphrase string) []byte {
	salt, _ := hex.DecodeString("deadbeef")
	return pbkdf2.Key([]byte(passphrase), salt, 1024, 256, sha1.New)[:32]
}
