package pki

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func ParseRSAPrivateKeyFromPEMWithPassword(key []byte, password string) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	}

	var parsedKey interface{}

	var blockDecrypted []byte
	if blockDecrypted, err = x509.DecryptPEMBlock(block, []byte(password)); err != nil {
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
	encKey := os.Getenv("KEY_PASS")
	if encKey != "" {
		if pkey, err := ParseRSAPrivateKeyFromPEMWithPassword(keyPEMBlock, encKey); err == nil {
			keyPEMBlock = ParseRSAPrivateKeyToMemory(pkey)
		}
	}
	cert, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	return cert, err
}
