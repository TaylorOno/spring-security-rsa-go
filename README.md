This little project provides some compatability with
[spring-security-rsa](https://github.com/dsyer/spring-security-rsa)
This is encryption used by [config-server](https://docs.pivotal.io/spring-cloud-services/3-1/common/config-server/)

```go
encryptor, _ := NewRSASecretEncryptorBuilder().Build()
encrypted, _ := encryptor.Encrypt("test")
plaintext, _ := encryptor.Decrypt(encrypted)
```

Above we create an encryptor with a random RSA key (the default
constructor), and use it to encrypt and then decrypt a message. the
default constructor is useful for testing, but for more durable use
cases you can inject a private key or public key before building the encryptor.

The encryption algorithm in the `RsaSecretEncryptor` is to generate a
random 16-byte password, and use that to encrypt the message. The
password is then itself RSA encrypted and prepended to the cipher
text. The cipher test is base64 encoded (if using the `TextEncryptor`
interface).

The other algorithm is in the `RsaRawEncryptor` which does raw RSA
encryption on the whole message. Config server utilizes RsaSecretEncryptor
