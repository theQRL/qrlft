package verify

import (
	"encoding/hex"
	"errors"
	"fmt"
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
	// Validate and decode signature
	fSig, err := hex.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(fSig) != dilithium.CRYPTO_BYTES {
		return false, fmt.Errorf("invalid signature length: got %d, expected %d", len(fSig), dilithium.CRYPTO_BYTES)
	}

	var sigBytes [dilithium.CRYPTO_BYTES]uint8
	copy(sigBytes[:], fSig)

	// Validate and decode public key
	pkBytes, err := PKHStrToBin(pk)
	if err != nil {
		return false, err
	}

	return dilithium.Verify(message, sigBytes, &pkBytes), nil
}

// PKHStrToBin converts a public key hex string to binary array (Dilithium)
func PKHStrToBin(pkHStr string) ([dilithium.CRYPTO_PUBLIC_KEY_BYTES]uint8, error) {
	var pk [dilithium.CRYPTO_PUBLIC_KEY_BYTES]uint8

	if len(pkHStr) != 2*dilithium.CRYPTO_PUBLIC_KEY_BYTES {
		return pk, fmt.Errorf("invalid public key length: got %d hex chars, expected %d", len(pkHStr), 2*dilithium.CRYPTO_PUBLIC_KEY_BYTES)
	}

	pkDecode, err := hex.DecodeString(pkHStr)
	if err != nil {
		return pk, fmt.Errorf("invalid public key hex: %w", err)
	}

	copy(pk[:], pkDecode)
	return pk, nil
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
	defer func() { _ = file.Close() }()

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
