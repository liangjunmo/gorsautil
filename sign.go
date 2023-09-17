package gorsautil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

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

func SignHTTPRequestWithSHA256(privateKey *rsa.PrivateKey, method string, url string, timestamp int64, random string, body string) (string, error) {
	return SignWithSHA256(privateKey, BuildSignMessage(method, url, timestamp, random, body))
}

func BuildSignMessage(method string, url string, timestamp int64, random string, body string) string {
	return fmt.Sprintf("%s\n%s\n%d\n%s\n%s\n", method, url, timestamp, random, body)
}
