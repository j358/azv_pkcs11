package main

// Build with go build -buildmode=c-archive -o libazv.a

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

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "test" {
			test.RunTest()
		}
	}
}

//export AzvInit
func AzvInit() int {
	println("Initializing azvlib package")

	doFree = false

	err := signer.CreateSigner(config.KeyVaultName)
	if err != nil {
		println("Failed to create signer: " + err.Error())
		return -1
	}

	return 0
}

//export AzvCancel
func AzvCancel() {
	println("Cancelling azvlib package")
	freeReturn()
	signer.DestroySigner()
}

func freeReturn() {
	if doFree {
		if ret != nil {
			C.free(ret)
			ret = nil
		}
		doFree = false
	}
}

func setReturnChar(cs *C.char) *C.char {
	freeReturn()
	ret = unsafe.Pointer(cs)
	doFree = true
	return cs
}

func setReturnByte(cs unsafe.Pointer) unsafe.Pointer {
	freeReturn()
	ret = cs
	doFree = true
	return ret
}

//export AzvGetVaultKeyCount
func AzvGetVaultKeyCount() int {
	return len(signer.KeyList)
}

//export AzvGetKeyListName
func AzvGetKeyListName(index int) *C.char {
	if index < 0 || index >= len(signer.KeyList) {
		println("index out of range")
		return nil
	}

	keyName := signer.KeyList[index].KeyName
	return setReturnChar(C.CString(keyName))
}

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

//export AzvGetKeyIndex
func AzvGetKeyIndex() int {
	if signer.KeyIndex < 0 || signer.KeyIndex >= len(signer.KeyList) {
		println("key index out of range")
		return -5
	}
	return signer.KeyIndex
}

//export AzvGetVaultName
func AzvGetVaultName() *C.char {
	// This function can be used to retrieve the vault name if needed
	return setReturnChar(C.CString(signer.VaultName))
}

//export AzvGetKeyName
func AzvGetKeyName() *C.char {
	// This function can be used to retrieve the key name if needed
	return setReturnChar(C.CString(signer.KeyName))
}

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

//export AzvGetCertIdLen
func AzvGetCertIdLen() C.size_t {
	return C.size_t(len(signer.KeyCert.X509Thumbprint))
}

//export AzvGetCertId
func AzvGetCertId() unsafe.Pointer {
	return setReturnByte(C.CBytes(signer.KeyCert.X509Thumbprint))
}

//export AzvGetUTC
func AzvGetUTC() *C.char {
	// This function can be used to retrieve the current UTC time
	utcTime := time.Now().UTC().Format(time.RFC3339)
	return setReturnChar(C.CString(utcTime))
}

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
