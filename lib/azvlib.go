// Copyright (c) 2025 Joshua Lee https://github.com/j358
// See LICENSE file for details.

// This library implements an Azure Key Vault signer that conforms to the crypto.Signer interface
// It allows signing operations using keys stored in Azure Key Vault
// The library also provides functions to retrieve certificates associated with the keys
// The additional functionality is used by the top level package to provide a PKCS#11 interface

package lib

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// var ctxBg = context.Background()
var LOCAL_TEST_CERT_FILE = "ca_cert.pem"
var LOCAL_TEST_CERT_NAME = "TestCert"
var LOCAL_TEST_VAULT_NAME = "MyTestVault"

// Set client secret credentials here via environment variables
var AZ_SECRET, _ = os.LookupEnv("AZV_CLIENT_SECRET")
var AZ_TENANT_ID, _ = os.LookupEnv("AZ_TENANT_ID")
var AZ_CLIENT_ID, _ = os.LookupEnv("AZ_CLIENT_ID")

var logMode, _ = os.LookupEnv("AZV_LOG_MODE")

type Pkcs1PublicKey struct {
	N *big.Int
	E int
}

type keyMap struct {
	KeyName    string
	KeyVersion string
}
type certMap struct {
	CertName    string
	CertVersion string
	CertId      []byte
}

// AzvSigner implements the crypto.Signer interface for signing operations
type AzvSigner struct {
	PublicKey     *rsa.PublicKey
	AzKeysClient  *azkeys.Client
	AzCertsClient *azcertificates.Client
	params        azkeys.SignParameters
	KeyList       []keyMap
	CertList      []certMap
	KeyCert       azcertificates.Certificate

	VaultName string
	KeyName   string
	KeyIndex  int
}

// Manually set the client secret credentials instead of taking the values from environment variables
// Call this function before CreateSigner
func (cs *AzvSigner) SetClientSecretCreds(tenantId, clientId, clientSecret string) error {
	if tenantId == "" || clientId == "" || clientSecret == "" {
		return errors.New("tenantId, clientId, and clientSecret must be provided")
	}
	AZ_TENANT_ID = tenantId
	AZ_CLIENT_ID = clientId
	AZ_SECRET = clientSecret
	return nil
}

// Create a signer using the specified Azure Key Vault
// This function connects to the vault, lists keys and certificates, and prepares for signing operations
// It is generally followed by a setKey call to select a specific key for signing operations
func (cs *AzvSigner) CreateSigner(vault string) error {

	cs.VaultName = vault
	if cs.VaultName == "" {
		println("Vault name is empty, using default vault")
		cs.VaultName = LOCAL_TEST_VAULT_NAME
	}

	var cred azcore.TokenCredential
	var err error
	authOk := false

	cred, err = azidentity.NewClientSecretCredential(AZ_TENANT_ID, AZ_CLIENT_ID, AZ_SECRET, nil)
	if err != nil {
		println("Failed to create Azure secret credential: " + err.Error())
	}
	cs.AzKeysClient, err = azkeys.NewClient("https://"+cs.VaultName+".vault.azure.net/", cred, nil)
	if err != nil {
		println("Failed to create Azure Key Vault key client: " + err.Error())
	} else {
		authOk = true
	}

	// Load Azure Key Vault with default credentials
	if authOk == false {
		cred, err = azidentity.NewDefaultAzureCredential(nil)
		if err == nil {
			cs.AzKeysClient, err = azkeys.NewClient("https://"+cs.VaultName+".vault.azure.net/", cred, nil)
			if err != nil {
				println("Failed to create Azure Key Vault key client: " + err.Error())
			} else {
				authOk = true
			}
		} else {
			println("Failed to create Azure credential: " + err.Error())
		}
	}

	// Also attempt device code - not very good as the object does not stay logged in
	if authOk == false {
		credCode, err := azidentity.NewDeviceCodeCredential(nil)
		if err != nil {
			println("Failed to create Azure device code credential: " + err.Error())
		} else {
			cs.AzKeysClient, err = azkeys.NewClient("https://"+cs.VaultName+".vault.azure.net/", credCode, nil)
			if err != nil {
				println("Failed to create Azure Key Vault key client: " + err.Error())
			} else {
				cred = credCode
				authOk = true
			}
		}
	}

	if authOk == false {
		println("No auth successful: " + err.Error())
		return err
	} else {
		println("cred created ok")
	}

	// List keys and populate keyList
	if logMode == "1" {
		println("Listing keys in Azure Key Vault: ", cs.VaultName)
	}
	keysPager := cs.AzKeysClient.NewListKeyPropertiesPager(nil)
	for keysPager.More() {
		page, err := keysPager.NextPage(context.TODO())
		if err != nil {
			println("Failed to list keys: " + err.Error())
			return err
		}
		for _, key := range page.Value {
			if logMode == "1" {
				println("    Key Name,Ver: ", key.KID.Name(), " ", key.KID.Version())
			}
			cs.KeyList = append(cs.KeyList, keyMap{
				KeyName:    key.KID.Name(),
				KeyVersion: key.KID.Version(),
			})
		}
	}
	if len(cs.KeyList) == 0 {
		println("No keys found in Azure Key Vault")
		return errors.New("no keys found in Azure Key Vault")
	} else {
		if logMode == "1" {
			println("-> Keys found in Azure Key Vault: ", len(cs.KeyList))
		}
	}

	cs.AzCertsClient, err = azcertificates.NewClient("https://"+cs.VaultName+".vault.azure.net/", cred, nil)
	if err != nil {
		println("Failed to create Azure Key Vault cert client: " + err.Error())
		return err
	}

	// List certs and populate certList
	if logMode == "1" {
		println("Listing certificates in Azure Key Vault: ", cs.VaultName)
	}
	certsPager := cs.AzCertsClient.NewListCertificatePropertiesPager(nil)
	for certsPager.More() {
		page, err := certsPager.NextPage(context.TODO())
		if err != nil {
			println("Failed to list certificates: " + err.Error())
			return err
		}
		for _, cert := range page.Value {
			if logMode == "1" {
				println("    Certificate Name,Ver: ", cert.ID.Name(), " ", cert.ID.Version(), " ")
			}
			cs.CertList = append(cs.CertList, certMap{
				CertName:    cert.ID.Name(),
				CertVersion: cert.ID.Version(),
				CertId:      cert.X509Thumbprint,
			})
		}
	}
	if len(cs.CertList) == 0 {
		println("No certificates found in Azure Key Vault")
		return errors.New("no certificates found in Azure Key Vault")
	} else {
		if logMode == "1" {
			println("-> Certificates found in Azure Key Vault: ", len(cs.CertList))
		}
	}

	return nil
}

// DestroySigner cleans up the AzvSigner by setting clients to nil and emptying parameters
func (cs *AzvSigner) DestroySigner() {
	if cs.AzKeysClient != nil {
		println("Destroying Azure Key Vault client")
		cs.AzKeysClient = nil
	} else {
		println("Azure Key Vault client is already nil")
	}
	if cs.AzCertsClient != nil {
		println("Destroying Azure Certificate client")
		cs.AzCertsClient = nil
	} else {
		println("Azure Certificate client is already nil")
	}
	cs.PublicKey = nil
	cs.params = azkeys.SignParameters{}
}

// crypto.Signer interface implementation for Public Key
func (cs *AzvSigner) Public() crypto.PublicKey {
	//println("Public Key: ", cs.publicKey.Size(), " bytes")
	return cs.PublicKey
}

// crypto.Signer interface implementation for Sign
func (cs *AzvSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if cs.AzKeysClient == nil {
		return nil, errors.New("Azure Key Vault client is not initialized")
	}
	cs.params.Value = digest
	switch len(digest) {
	case 32:
		alg := azkeys.SignatureAlgorithmRS256
		cs.params.Algorithm = &alg
	case 64:
		alg := azkeys.SignatureAlgorithmRS512
		cs.params.Algorithm = &alg
	default:
		return nil, errors.New("unsupported digest length: " + fmt.Sprint(len(digest)))
	}

	// Sign the digest
	signature, err := cs.AzKeysClient.Sign(context.TODO(), cs.KeyName, "", cs.params, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}

	return signature.Result, nil
}

// PkcsSign is not currently supported
func (cs *AzvSigner) PkcsSign(data []byte, signType string) ([]byte, error) {
	if cs.AzKeysClient == nil {
		return nil, errors.New("Azure Key Vault client is not initialized")
	}

	if signType != "RSA" {
		return nil, errors.New("unsupported sign type: " + signType)
	}

	return nil, errors.New("sign not supported")

	/*
		// Not properly tested

			alg := azkeys.JSONWebKeyEncryptionAlgorithmRSA15
			ep := azkeys.KeyOperationsParameters{
				Value:     data,
				Algorithm: &alg,
			}

			resp, err := cs.AzKeysClient.Encrypt(*cs.ctx, cs.KeyName, "", ep, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt data: %w", err)
			}

			return resp.Result, nil
	*/
}

// DigestAndSign computes the SHA256 digest of the input data and signs it using the specified sign type
// Currently, only SHA256 digest and RSA sign types are supported
func (cs *AzvSigner) DigestAndSign(data []byte, digestType string, signType string) (signature []byte, err error) {
	if digestType != "SHA256" {
		return nil, errors.New("unsupported digest type: " + signType)
	}

	digest := crypto.SHA256.New()
	_, err = digest.Write(data)
	if err != nil {
		return nil, errors.New("Failed to write data to digest: " + err.Error())
	}
	sha := digest.Sum(nil)
	//fmt.Printf("Digest for signing: %x\n", sha)

	if signType != "RSA" {
		return nil, errors.New("unsupported sign type: " + signType)
	}

	sig, err := cs.Sign(rand.Reader, sha, nil)
	if err != nil {
		return nil, errors.New("Failed to sign digest: " + err.Error())
	}
	//fmt.Printf("Signature: \n%x\n", sig)

	return sig, nil
}

// CheckSigner verifies that the provided signer implements the crypto.Signer interface
// and checks the type of the public key
func CheckSigner(signer any) {
	s, ok := signer.(crypto.Signer)
	if !ok {
		panic("Signer does not implement crypto.Signer interface")
	}
	if _, ok := signer.(crypto.Decrypter); !ok {
		println("Signer does not implement crypto.Decrypter interface")
	}
	if _, ok := signer.(crypto.SignerOpts); !ok {
		println("Signer does not implement crypto.SignerOpts interface")
	}

	switch s.Public().(type) {
	case *rsa.PublicKey:
		println("Public key is *RSA")
	case rsa.PublicKey:
		println("Public key is RSA")
	case *ecdsa.PublicKey:
		println("Public key is ECDSA")
	default:
		panic("Public key is of unknown type")
	}
}

// SetKey selects a key from Azure Key Vault by name and retrieves its public key
// If the key name is empty, it defaults to a predefined local test certificate name
// The public key is extracted and prepared for signing operations
func (cs *AzvSigner) SetKey(keyName string) error {
	if cs.AzKeysClient == nil {
		return errors.New("Azure Key Vault client is not initialized")
	}
	if keyName == "" {
		println("Key name is empty, using default key")
		cs.KeyName = LOCAL_TEST_CERT_NAME
	} else {
		cs.KeyName = keyName
		println("  Using key: ", cs.KeyName)
	}

	// Get the public key from Azure Key Vault
	key, err := cs.AzKeysClient.GetKey(context.TODO(), cs.KeyName, "", nil)
	if err != nil {
		println("Failed to get key from Azure Key Vault: " + err.Error())
		return err
	}
	println("  Key Name: ", key.Key.KID.Name())

	pubKeyModBytes := key.Key.N
	pubKeyExpBytes := key.Key.E
	if pubKeyModBytes == nil || pubKeyExpBytes == nil {
		return errors.New("public key modulus or exponent is nil")
	}
	println("  Public Key Modulus Length: ", len(pubKeyModBytes))

	// Convert modulus (N) from []byte to *big.Int
	pubKeyMod := new(big.Int).SetBytes(pubKeyModBytes)

	// Convert exponent (E) from []byte to int
	var pubKeyExp int
	for _, b := range pubKeyExpBytes {
		pubKeyExp = pubKeyExp<<8 + int(b)
	}

	cs.PublicKey = &rsa.PublicKey{
		N: pubKeyMod,
		E: pubKeyExp,
	}

	// Print public key
	// fmt.Printf("Public Key: N=%s, E=%d\n", cs.publicKey.N.String(), cs.publicKey.E)

	a := azkeys.SignatureAlgorithmRS256
	cs.params = azkeys.SignParameters{
		Algorithm: &a,
	}

	return nil
}

// GetCertForKey retrieves the certificate associated with the specified key from Azure Key Vault
func (cs *AzvSigner) GetCertForKey() error {
	if cs.AzCertsClient == nil {
		return errors.New("Azure Key Vault certificate client is not initialized")
	}
	if cs.KeyName == "" {
		return errors.New("key name is empty")
	}

	if cs.KeyName == LOCAL_TEST_CERT_NAME {
		println("Using default key name: ", LOCAL_TEST_CERT_NAME)
		return nil
	}

	cert, err := cs.AzCertsClient.GetCertificate(context.TODO(), cs.KeyName, "", nil)
	if err != nil {
		return errors.New("Failed to get certificate from Azure Key Vault: " + err.Error())
	}
	cs.KeyCert = cert.Certificate
	println("  Certificate Name: ", cs.KeyCert.ID.Name())

	return nil
}

// GetCertBytes retrieves the certificate bytes in DER format
func (cs *AzvSigner) GetCertBytes() ([]byte, error) {
	if cs.KeyName == LOCAL_TEST_CERT_NAME {
		// Read in the cert data in PEM format
		certPEM, err := os.ReadFile(LOCAL_TEST_CERT_FILE)
		if err != nil {
			return nil, errors.New("Failed to read certificate PEM file: " + err.Error())
		}
		// Convert PEM to DER format
		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("CERTIFICATE BLOCK NOT FOUND")
		}
		return block.Bytes, nil
	}

	if cs.KeyCert.ID.Name() == "" {
		return nil, errors.New("certificate is not set")
	}
	return cs.KeyCert.CER, nil
}
