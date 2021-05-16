package rsa_textencryptor

type TextEncryptor interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}
