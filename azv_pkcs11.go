// Copyright (c) 2025 Joshua Lee https://github.com/j358
// See LICENSE file for details.

// This file contains the C bindings for the azv_pkcs11 library
// Build with go build -buildmode=c-archive -o libazv.a
// Additional logging can be activated by setting the AZV_LOG_MODE environment variable to 1 (console) or 2 (file)

package main

// #include <stdio.h>
// #include <errno.h>
// #include <stdlib.h>
import "C"
import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/j358/azv_pkcs11/config"
	"github.com/j358/azv_pkcs11/lib"
	"github.com/j358/azv_pkcs11/test"
)

//export signer
var signer lib.AzvSigner
var logName = "/var/log/azvlib.log"
var logMode, _ = os.LookupEnv("AZV_LOG_MODE")
var ret unsafe.Pointer
var doFree = false

/*
ASN.1 structure for EncryptedPrivateKeyInfo
Used for decoding the input to AzvSign_RSA_PKCS when it is not a raw hash
The structure is defined in PKCS#8 (RFC 5208)

EncryptedPrivateKeyInfo SEQUENCE (2 elem)
    encryptionAlgorithm AlgorithmIdentifier SEQUENCE (2 elem)
        algorithm OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 sha-256 (NIST Algorithm)
        parameters ANY NULL
    encryptedData EncryptedData OCTET STRING (32 byte) EF9E23F6E1DAD35F05DF5B647294E4422039C810AE823F1315EFD8D674872C3C
*/

type EncryptedPrivateKeyInfo struct {
	ENCRYPTIONALGORITHM AlgorithmIdentifier
	ENCRYPTEDDATA       []byte
}
type AlgorithmIdentifier struct {
	ALGORITHM  asn1.ObjectIdentifier
	PARAMETERS asn1.RawValue // should be NULL
}

// Normally this file is built as a library, but if run directly it can perform tests
func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "test" {
			test.RunTest()
		}
	}
}

// AzvInit initializes the azvlib package and creates the Azure Key Vault signer
//
//export AzvInit
func AzvInit() int {
	println("Initializing azvlib package")

	doFree = false

	if config.DefaultAzTenantId != "" {
		println("Using stored credentials")
		signer.SetClientSecretCreds(config.DefaultAzTenantId, config.DefaultAzClientId, config.DefaultAzClientSecret)
	}

	err := signer.CreateSigner(config.KeyVaultName)
	if err != nil {
		println("Failed to create signer: " + err.Error())
		return -1
	}

	return 0
}

// AzvCancel cleans up the azvlib package and frees resources
// A non-deterministic sequence of module closing can cause segmentation faults
// e.g. if using openssl engine interface, libp11 0.4.16, and azv_pkcs11 together
// one workaround was to stop libp11 from closing the loaded module early with a patch:
// sed -i 's/dlclose(mod->handle);/return CKR_OK; dlclose(mod->handle);/' /usr/src/libp11-0.4.16/src/libpkcs11.c
//
//export AzvCancel
func AzvCancel() {
	println("Cancelling azvlib package")
	freeReturn()
	signer.DestroySigner()
}

// freeReturn frees the memory allocated for the return value if needed
// Any functions that allocate memory for return values set doFree to true
// and store the pointer in ret.
func freeReturn() {
	if doFree {
		if ret != nil {
			C.free(ret)
			ret = nil
		}
		doFree = false
	}
}

// setReturnChar sets the return value to a C string and manages memory
// It frees any previously allocated return value before setting the new one
// It sets doFree to true to indicate that the memory should be freed later
// It returns the C string pointer
func setReturnChar(cs *C.char) *C.char {
	freeReturn()
	ret = unsafe.Pointer(cs)
	doFree = true
	return cs
}

// setReturnByte sets the return value to a byte array and manages memory
// It frees any previously allocated return value before setting the new one
// It sets doFree to true to indicate that the memory should be freed later
// It returns the byte array pointer
func setReturnByte(cs unsafe.Pointer) unsafe.Pointer {
	freeReturn()
	ret = cs
	doFree = true
	return ret
}

// AzvGetVaultKeyCount returns the number of keys available in the vault
//
//export AzvGetVaultKeyCount
func AzvGetVaultKeyCount() int {
	return len(signer.KeyList)
}

// AzvGetKeyListName returns the name of the key at the given index
// Returns NULL if the index is out of range
//
//export AzvGetKeyListName
func AzvGetKeyListName(index int) *C.char {
	if index < 0 || index >= len(signer.KeyList) {
		println("index out of range")
		return nil
	}

	keyName := signer.KeyList[index].KeyName
	return setReturnChar(C.CString(keyName))
}

// AzvSetKeyIndex sets the current key to the key at the given index
// Returns 0 on success, or a negative error code on failure
//
//export AzvSetKeyIndex
func AzvSetKeyIndex(index int) int {
	if index < 0 || index >= len(signer.KeyList) {
		println("index out of range")
		return -3
	}

	err := signer.SetKey(signer.KeyList[index].KeyName)
	if err != nil {
		println("Failed to set key: " + err.Error())
		return -4
	}

	signer.KeyIndex = index
	return 0
}

// AzvGetKeyIndex returns the current key index
// Returns -5 if the index is out of range
//
//export AzvGetKeyIndex
func AzvGetKeyIndex() int {
	if signer.KeyIndex < 0 || signer.KeyIndex >= len(signer.KeyList) {
		println("key index out of range")
		return -5
	}
	return signer.KeyIndex
}

// AzvGetVaultName returns the name of the vault configured when the signer was created
//
//export AzvGetVaultName
func AzvGetVaultName() *C.char {
	// This function can be used to retrieve the vault name if needed
	return setReturnChar(C.CString(signer.VaultName))
}

// AzvGetKeyName returns the name of the current key
//
//export AzvGetKeyName
func AzvGetKeyName() *C.char {
	// This function can be used to retrieve the key name if needed
	return setReturnChar(C.CString(signer.KeyName))
}

// AzvSign_RSA_PKCS signs the given data using the current key and returns the signature
// The data can be either a raw hash (32 or 64 bytes) or an ASN.1 encoded EncryptedPrivateKeyInfo structure
// If the data is not a raw hash, it is ASN.1 decoded to extract the encrypted data
//
//export AzvSign_RSA_PKCS
func AzvSign_RSA_PKCS(data *byte, dataLen C.size_t, sigLen *C.size_t) unsafe.Pointer {
	if signer.AzKeysClient == nil {
		println("Azure Key Vault client is not initialized")
		return nil
	}

	var dataBytes []byte

	println("AzvSign_RSA_PKCS: dataLen:", dataLen)

	if dataLen != 32 && dataLen != 64 {
		//perform ASN1 decode
		var s EncryptedPrivateKeyInfo
		_, err := asn1.Unmarshal(C.GoBytes(unsafe.Pointer(data), C.int(dataLen)), &s)
		if err != nil {
			println("Failed to unmarshal data: " + err.Error())
			return nil
		}
		if logMode == "1" {
			println("Unmarshalled EncryptedPrivateKeyInfo:")
			fmt.Printf("Algorithm: %s\n", s.ENCRYPTIONALGORITHM.ALGORITHM.String())
			fmt.Printf("Encrypted Data: %x\n", s.ENCRYPTEDDATA)
			println("Encrypted Data Length: ", len(s.ENCRYPTEDDATA))
		}
		if len(s.ENCRYPTEDDATA) != 32 && len(s.ENCRYPTEDDATA) != 64 {
			println("Encrypted data length is not 32 or 64 bytes")
			return nil
		}
		dataBytes = s.ENCRYPTEDDATA
	} else {
		dataBytes = C.GoBytes(unsafe.Pointer(data), C.int(dataLen))
	}

	//signature, err := signer.PkcsSign(dataBytes, "RSA")
	signature, err := signer.Sign(rand.Reader, dataBytes, nil)
	if err != nil {
		println("Failed to sign data: " + err.Error())
		return nil
	}
	*sigLen = C.size_t(len(signature))

	return setReturnByte(C.CBytes(signature))
}

// AzvSign_SHA256_RSA_PKCS computes the SHA256 digest of the given data and signs it using the current key
// The data is expected to be the raw data to be hashed and signed
//
//export AzvSign_SHA256_RSA_PKCS
func AzvSign_SHA256_RSA_PKCS(data *byte, dataLen C.size_t, sigLen *C.size_t) unsafe.Pointer {
	if signer.AzKeysClient == nil {
		println("Azure Key Vault client is not initialized")
		return nil
	}

	dataBytes := C.GoBytes(unsafe.Pointer(data), C.int(dataLen))
	signature, err := signer.DigestAndSign(dataBytes, "SHA256", "RSA")
	if err != nil {
		println("Failed to sign data: " + err.Error())
		return nil
	}
	*sigLen = C.size_t(len(signature))

	return setReturnByte(C.CBytes(signature))
}

// AzvGetKeyExponent returns the public key exponent of the current key
//
//export AzvGetKeyExponent
func AzvGetKeyExponent() unsafe.Pointer {
	if signer.AzKeysClient == nil {
		println("Azure Key Vault client is not initialized")
		return nil
	}

	if signer.PublicKey.E == 0 {
		println("Public key exponent is not set or invalid")
		return nil
	}

	exponent := make([]byte, 4)
	exponent[0] = byte(signer.PublicKey.E >> 24)
	exponent[1] = byte(signer.PublicKey.E >> 16)
	exponent[2] = byte(signer.PublicKey.E >> 8)
	exponent[3] = byte(signer.PublicKey.E)

	return setReturnByte(C.CBytes(exponent))
}

// AzvGetKeyModulusLen returns the length of the public key modulus in bytes
//
//export AzvGetKeyModulusLen
func AzvGetKeyModulusLen() C.size_t {
	if signer.AzKeysClient == nil {
		println("Azure Key Vault client is not initialized")
		return 0
	}

	if signer.PublicKey.N == nil {
		println("Public key modulus is not set or invalid")
		return 0
	}

	modulusLen := C.size_t(len(signer.PublicKey.N.Bytes()))
	if logMode == "1" {
		fmt.Printf("Modulus length: %d bytes\n", modulusLen)
	}

	return modulusLen
}

// AzvGetKeyModulus returns the public key modulus of the current key
//
//export AzvGetKeyModulus
func AzvGetKeyModulus() unsafe.Pointer {
	if signer.AzKeysClient == nil {
		println("Azure Key Vault client is not initialized")
		return nil
	}

	if (signer.PublicKey.E == 0) || (signer.PublicKey.N == nil) {
		println("Public key is not set or invalid")
		return nil
	}

	modulus := signer.PublicKey.N.Bytes()

	if modulus == nil {
		println("Key modulus is nil")
		return nil
	}
	// fmt.Printf("%02x%02x%02x%02x\n", modulus[0], modulus[1], modulus[2], modulus[3])
	// fmt.Printf("%02x%02x%02x%02x\n", modulus[508], modulus[509], modulus[510], modulus[511])

	return setReturnByte(C.CBytes(modulus))
}

// AzvLoadCert retrieves the certificate associated with the current key from Azure Key Vault
// The certificate is stored in the signer for later retrieval
//
//export AzvLoadCert
func AzvLoadCert() int {
	err := signer.GetCertForKey()
	if err != nil {
		println("Failed to get certificate: " + err.Error())
		return -1
	}
	if logMode == "1" {
		println("Certificate loaded successfully")
	}
	return 0
}

// AzvGetCertLen returns the length of the certificate in bytes
//
//export AzvGetCertLen
func AzvGetCertLen() C.size_t {
	b, err := signer.GetCertBytes()
	if err != nil {
		println("Failed to get certificate bytes: " + err.Error())
		return 0
	}
	if b == nil {
		println("Certificate bytes are nil")
		return 0
	}
	if logMode == "1" {
		fmt.Printf("Certificate length: %d bytes\n", len(b))
	}
	return C.size_t(len(b))
}

// AzvGetCert returns the certificate in DER format as a byte array
//
//export AzvGetCert
func AzvGetCert() unsafe.Pointer {
	certBytes, err := signer.GetCertBytes()
	if err != nil {
		println("Failed to get certificate bytes: " + err.Error())
		return nil
	}
	if certBytes == nil {
		println("Certificate bytes are nil")
		return nil
	}

	if logMode == "1" {
		fmt.Printf("Certificate length: %d bytes\n", len(certBytes))
	}

	return setReturnByte(C.CBytes(certBytes))
}

// AzvGetCertIdLen returns the length of the certificate thumbprint in bytes
//
//export AzvGetCertIdLen
func AzvGetCertIdLen() C.size_t {
	return C.size_t(len(signer.KeyCert.X509Thumbprint))
}

// AzvGetCertId returns the certificate thumbprint
//
//export AzvGetCertId
func AzvGetCertId() unsafe.Pointer {
	return setReturnByte(C.CBytes(signer.KeyCert.X509Thumbprint))
}

// AzvGetUTC returns the current UTC time as a string in RFC3339 format
//
//export AzvGetUTC
func AzvGetUTC() *C.char {
	utcTime := time.Now().UTC().Format(time.RFC3339)
	return setReturnChar(C.CString(utcTime))
}

// AzvLog is a logging function that can be called from C code
// It logs messages to the console or a file based on the AZV_LOG_MODE environment variable
//
//export AzvLog
func AzvLog(msg *C.char) {
	// This function can be used to log messages from C code
	goMsg := C.GoString(msg)
	if logMode == "1" || logMode == "2" {
		println("C: " + goMsg)
		if logMode == "2" {
			file, err := os.OpenFile(logName, os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				file.WriteString("C: " + goMsg + "\n")
				file.Close()
			}
		}
	}
}
