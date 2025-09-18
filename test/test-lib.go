package test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	lib "github.com/j358/azv_pkcs11/lib"
)

var LOCAL_TEST_CERT_FILE = "ca_cert.pem"
var LOCAL_TEST_CERT_NAME = "TestCert"
var LOCAL_TEST_VAULT_NAME = "MyTestVault"

var ctx = context.Background()

func RunTest() {

	var signer lib.AzvSigner
	var err error

	err = signer.CreateSigner(LOCAL_TEST_VAULT_NAME)
	if err != nil {
		panic("Failed to create signer: " + err.Error())
	}
	err = signer.SetKey(LOCAL_TEST_CERT_NAME)
	if err != nil {
		panic("Failed to set key: " + err.Error())
	}

	// Read in CSR Data in PEM format
	csrPEM, err := os.ReadFile("test/ca_cert_req.pem")

	// Convert PEM to DER format
	if err != nil {
		panic("Failed to read CSR PEM file: " + err.Error())
	}
	block, _ := pem.Decode(csrPEM)
	// Check correct block found
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		panic("CERTIFICATE REQUEST BLOCK NOT FOUND")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	pubKey := signer.Public()

	// Force RSA algorithm
	csr.SignatureAlgorithm = x509.SHA256WithRSA
	csr.PublicKeyAlgorithm = x509.RSA

	// Calculate Authority Key Identifier
	publicKeyBytes, err := asn1.Marshal(lib.Pkcs1PublicKey{
		N: pubKey.(*rsa.PublicKey).N,
		E: pubKey.(*rsa.PublicKey).E,
	})
	ski := sha1.Sum(publicKeyBytes)
	// print hexadecimal representation of the Authority Key Identifier
	fmt.Printf("Authority Key Identifier: % X\n", ski)
	skiStr := fmt.Sprintf("% X", ski)
	skiStr = strings.Replace(skiStr, " ", ":", -1)

	// Create new Certificate
	certTemplate := &x509.Certificate{
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             pubKey,
		SerialNumber:          big.NewInt(1658),
		Issuer:                csr.Subject,
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(time.Hour * 24 * 365 * -1),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 100),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		AuthorityKeyId:        ski[:],
		// ExtraExtensions: []pkix.Extension{{
		// 	Id:       asn1.ObjectIdentifier{2, 5, 29, 35},
		// 	Critical: false,
		// 	Value:    []byte(skiStr),
		// }},
	}

	_ = certTemplate

	// Check if the signer implements the crypto.Signer interface and is RSA
	lib.CheckSigner(&signer)

	// Perform a test signing operation
	testStr := "This is a test string for signing"
	digest := crypto.SHA256.New()
	_, err = digest.Write([]byte(testStr))
	sha := digest.Sum(nil)
	fmt.Printf("Digest for signing: %x\n", sha)
	sig, err := signer.Sign(rand.Reader, sha, nil)
	if err != nil {
		panic("Failed to sign digest: " + err.Error())
	}
	fmt.Printf("Signature: \n%x\n", sig)

	// Verify the test signature
	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, sha, sig)
	if err != nil {
		panic("Signature verification failed: " + err.Error())
	} else {
		println("Signature verification succeeded")
	}

	// Sign the CSR with Azure Key Vault
	certData, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, certTemplate.PublicKey.(*rsa.PublicKey), &signer)
	if err != nil {
		panic("Failed to create certificate: " + err.Error())
	}

	// Save the signed certificate
	err = os.WriteFile("test/"+LOCAL_TEST_CERT_FILE, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certData}), 0644)
}
