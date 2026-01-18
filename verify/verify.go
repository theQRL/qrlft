package verify

import (
	"encoding/hex"
	"errors"
	"os"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
	"github.com/theQRL/qrlft/crypto"
)

// VerifyFile verifies a signature against a file (Dilithium, for backward compatibility)
func VerifyFile(filename string, signature string, pk string) (bool, error) {
	message, err := readFile(filename)
	if err != nil {
		return false, err
	}
	return VerifyMessage(message, signature, pk)
}

// VerifyMessage verifies a signature against a message (Dilithium, for backward compatibility)
func VerifyMessage(message []byte, signature string, pk string) (bool, error) {
	var sigBytes [dilithium.CRYPTO_BYTES]uint8
	fSig, _ := hex.DecodeString(signature)
	copy(sigBytes[:], fSig)

	pkBytes := PKHStrToBin(pk)

	return dilithium.Verify(message, sigBytes, &pkBytes), nil
}

// PKHStrToBin converts a public key hex string to binary array (Dilithium)
func PKHStrToBin(pkHStr string) [dilithium.CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	if len(pkHStr) != 2*dilithium.CRYPTO_PUBLIC_KEY_BYTES {
		panic("Invalid pkHStr")
	}
	var pk [dilithium.CRYPTO_PUBLIC_KEY_BYTES]uint8
	pkDecode, _ := hex.DecodeString(pkHStr)

	copy(pk[:], pkDecode)

	return pk
}

// VerifyFileWithVerifier verifies a signature against a file using a Verifier interface
func VerifyFileWithVerifier(filename string, signature string, pk string, verifier crypto.Verifier) (bool, error) {
	message, err := readFile(filename)
	if err != nil {
		return false, err
	}
	return VerifyMessageWithVerifier(message, signature, pk, verifier)
}

// VerifyMessageWithVerifier verifies a signature against a message using a Verifier interface
func VerifyMessageWithVerifier(message []byte, signature string, pk string, verifier crypto.Verifier) (bool, error) {
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, errors.New("failed to decode signature: " + err.Error())
	}

	pkBytes, err := hex.DecodeString(pk)
	if err != nil {
		return false, errors.New("failed to decode public key: " + err.Error())
	}

	return verifier.Verify(message, sigBytes, pkBytes), nil
}

// VerifyFileWithAlgorithm verifies a signature against a file using the specified algorithm
func VerifyFileWithAlgorithm(filename string, signature string, pk string, algorithm string, context []byte) (bool, error) {
	verifier, err := crypto.NewVerifier(algorithm, context)
	if err != nil {
		return false, err
	}
	return VerifyFileWithVerifier(filename, signature, pk, verifier)
}

// VerifyMessageWithAlgorithm verifies a signature against a message using the specified algorithm
func VerifyMessageWithAlgorithm(message []byte, signature string, pk string, algorithm string, context []byte) (bool, error) {
	verifier, err := crypto.NewVerifier(algorithm, context)
	if err != nil {
		return false, err
	}
	return VerifyMessageWithVerifier(message, signature, pk, verifier)
}

// readFile reads the entire contents of a file
func readFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileinfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if fileinfo.IsDir() {
		return nil, errors.New("file is a directory")
	}

	filesize := fileinfo.Size()
	buffer := make([]byte, filesize)

	bytesread, err := file.Read(buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:bytesread], nil
}
