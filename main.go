package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func main() {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)

	privateKey := x509.MarshalPKCS1PrivateKey(key)
	savePEMKey("private_key.pem", privateKey, "RSA PRIVATE KEY")

	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	checkError(err)
	savePEMKey("public_key.pem", publicKey, "PUBLIC KEY")
}

func savePEMKey(fileName string, keyBytes []byte, keyType string) {
	outFile, err := os.Create(fileName)
	checkError(err)

	var pemKey = &pem.Block{
		Type:    keyType,
		Headers: nil,
		Bytes:   keyBytes,
	}

	pem.Encode(outFile, pemKey)
	outFile.Close()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
