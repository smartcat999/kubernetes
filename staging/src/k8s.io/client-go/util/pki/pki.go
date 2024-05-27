package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
)

var Data string
var (
	defaultKeyPass = "/etc/kubernetes/default-flags.conf"
)

func ParseRSAPrivateKeyFromPEMWithPassword(key []byte) (*rsa.PrivateKey, error) {
	var err error
	keyEnv := os.Getenv("KEY_PASS")
	if keyEnv == "" {
		if _, err = os.Stat(defaultKeyPass); err != nil {
			return nil, nil
		}
		keyPassBytes, err := os.ReadFile(defaultKeyPass)
		if err != nil {
			return nil, nil
		}
		if len(keyPassBytes) == 0 {
			return nil, nil
		}
		keyEnv = string(keyPassBytes)
	}
	keyData, err := Decrypt(keyEnv, Data)
	if err != nil {
		return nil, err
	}

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	}

	var parsedKey interface{}

	var blockDecrypted []byte
	if blockDecrypted, err = x509.DecryptPEMBlock(block, keyData); err != nil {
		return nil, err
	}

	if parsedKey, err = x509.ParsePKCS1PrivateKey(blockDecrypted); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, errors.New("key is not a valid RSA private key")
	}

	return pkey, nil
}

func ParseRSAPrivateKeyToMemory(key *rsa.PrivateKey) []byte {
	keybytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keybytes,
	}
	return pem.EncodeToMemory(block)
}

func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	cert := tls.Certificate{}
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return cert, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return cert, err
	}
	if pkey, err := ParseRSAPrivateKeyFromPEMWithPassword(keyPEMBlock); err == nil && pkey != nil {
		keyPEMBlock = ParseRSAPrivateKeyToMemory(pkey)
	}
	cert, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	return cert, err
}

func Decrypt(plaintext string, key string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return nil, err
	}
	cipherKey, _ := hex.DecodeString(key)
	nonce := cipherKey[:12]

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	data, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func Encrypt(plaintext []byte, key string) (string, error) {
	cipherKey, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return "", err
	}

	nonce := cipherKey[:12]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	srcData := aesgcm.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(srcData), nil
}
