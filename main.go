package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	depot "github.com/square/certstrap/depot"
	pkix "github.com/square/certstrap/pkix"
)

func main() {
	reader := rand.Reader
	bitSize := 2048
	rsaKey, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)

	privateKey := x509.MarshalPKCS1PrivateKey(rsaKey)
	savePEMKey("private_key.pem", privateKey, "RSA PRIVATE KEY")

	publicKey, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	checkError(err)
	savePEMKey("public_key.pem", publicKey, "PUBLIC KEY")

	// certstrap code
	d, err := depot.NewFileDepot("")
	checkError(err)
	commonName := "common-name"
	//formattedName := strings.Replace(commonName, " ", "_", -1)
	var pkixKey *pkix.Key
	pkixKey, err = pkix.CreateRSAKey(2048)
	if err != nil {
		log.Fatal("Create RSA Key error:", err)
	}
	if err = depot.PutPrivateKey(d, "ca-key", pkixKey); err != nil {
		fmt.Fprintln(os.Stderr, "Save private key error:", err)
	}
	unit := ""
	years := 10
	org := ""
	country := ""
	province := ""
	locality := ""
	crt, err := pkix.CreateCertificateAuthority(pkixKey, unit, years, org, country, province, locality, commonName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create certificate error:", err)
		os.Exit(1)
	}
	if err = depot.PutCertificate(d, "ca", crt); err != nil {
		fmt.Fprintln(os.Stderr, "Save certificate error:", err)
	}
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
