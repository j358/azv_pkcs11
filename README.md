# azv_pkcs11
Go PKCS11 and Crypto.Signer interface for Azure Keyvault by Joshua Lee https://github.com/j358

[![Go Reference](https://pkg.go.dev/badge/github.com/j358/azv_pkcs11.svg)](https://pkg.go.dev/github.com/j358/azv_pkcs11)

## INTRO

Project based on the skeleton implementation for PKCS11 v3.2 handler here:
- https://github.com/Pkcs11Interop/empty-pkcs11/tree/master/src/cryptoki
- https://github.com/Pkcs11Interop/PKCS11-SPECS/blob/master/v2.20/pkcs-11v2-20a3.pdf

Uses the AZURE Go library to connect to Azure Keyvault
- https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys
- https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity

The terminal must be logged into Azure. Use: `az login --use-device-code --allow-no-subscriptions`

Note that the Go application also implements the crypto.Signer interface for use as a general signer across many Go libraries.
See `test_azvlib.go` for a sample implementation: `go run test_azvlib.go azvlib.go azv_cbind.go`

The Go application is compiled to a shared C library (libazv) for inclusion in the azv-pkcs11 project. This is done with cgo: https://pkg.go.dev/cmd/cgo


## EXAMPLE COMMANDS

    az login --allow-no-subscriptions --use-device-code
    az ad signed-in-user show

    az keyvault key show --vault-name MyTestVault --name MyTestCertificate

    az keyvault key download --vault-name MyTestVault --name MyTestCertificate --file MyTestCertificate.txt

    openssl rsa -in MyTestCertificate.txt -pubin -text

    pkcs11-tool --module=./azv-pkcs11-x64.so -L
    pkcs11-tool --module=./azv-pkcs11-x64.so -T
    pkcs11-tool --module=./azv-pkcs11-x64.so -s --slot 10000 -i test/testdata.txt -o signout.txt

    export PKCS11_MODULE_PATH=/usr/lib/x86_64-linux-gnu/ossl-modules/azv-pkcs11-x64.so
    export PKCS11_MODULE_PATH=/usr/local/lib/azv-pkcs11-x64.so
    openssl pkeyutl -sign -in testdata.txt -inkey "pkcs11:token=T-MyTestCertificate;type=private"
    openssl pkeyutl -sign -in testdata.txt -inkey "pkcs11:token=T-MyTestCertificate;type=private" -provider pkcs11prov

    openssl pkeyutl -sign -in testdata.txt -rawin -digest SHA-256 -inkey "pkcs11:token=T-MyTestCertificate;type=private" -out sigout2.bin
    openssl pkeyutl -verify -in testdata.txt -rawin -digest SHA-256 -inkey "pkcs11:token=T-MyTestCertificate;type=private" -sigfile sigout2.bin

    openssl x509 -in "pkcs11:token=T-MyTestCertificate;type=private" -text
