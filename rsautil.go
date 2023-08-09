package gorsautil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func NewPrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, fmt.Errorf("decode private key failed")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("pem type is not private key")
	}

	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %v", err)
	}

	return pk, nil
}

func NewPrivateKeyWithFile(file string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read private key file: %v", err)
	}

	return NewPrivateKey(string(b))
}

func NewPublicKey(publicKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, fmt.Errorf("decode public key failed")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("pem type is not public key")
	}

	pk, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %v", err)
	}

	return pk, nil
}

func NewPublicKeyWithFile(file string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %v", err)
	}

	return NewPublicKey(string(b))
}

func SignWithSHA256(privateKey *rsa.PrivateKey, message string) (string, error) {
	hash := crypto.Hash.New(crypto.SHA256)

	_, err := hash.Write([]byte(message))
	if err != nil {
		return "", fmt.Errorf("hash: %v", err)
	}

	hashed := hash.Sum(nil)

	signed, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signed), nil
}

func VerifySignatureWithSHA256(publicKey *rsa.PublicKey, message string, signature string) error {
	b, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("base64 decode: %v, signature: %s", err, signature)
	}

	hashed := sha256.Sum256([]byte(message))

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], b)
	if err != nil {
		return fmt.Errorf("verify signature: %v, message: %s, signature: %s", err, message, signature)
	}

	return nil
}

func SignHttpRequestWithSHA256(privateKey *rsa.PrivateKey, method string, url string, timestamp int64, random string, body string) (string, error) {
	return SignWithSHA256(privateKey, BuildSignMessage(method, url, timestamp, random, body))
}

func BuildSignMessage(method string, url string, timestamp int64, random string, body string) string {
	return fmt.Sprintf("%s\n%s\n%d\n%s\n%s\n", method, url, timestamp, random, body)
}
