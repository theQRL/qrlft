package sign

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
	"github.com/theQRL/qrlft/crypto"
)

// SignMessage signs a message using a hexseed (Dilithium, for backward compatibility)
func SignMessage(message []byte, hexseed string) (string, error) {
	d, err := dilithium.NewDilithiumFromHexSeed(hexseed)
	if err != nil {
		return "", fmt.Errorf("failed to generate dilithium from seed: %w", err)
	}

	signature, err := d.Sign(message)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %w", err)
	}
	return hex.EncodeToString(signature[:]), nil
}

// SignMessageWithPrivateKey signs a message using a private key (secret key) directly.
// The algorithm must match the key material: an ML-DSA-87 private key PEM is never
// silently signed with Dilithium. Use SignMessageWithPrivateKeyAndAlgorithm when the
// requested algorithm is known (as the CLI does).
func SignMessageWithPrivateKey(message []byte, privateKeyHex string) (string, error) {
	return SignMessageWithPrivateKeyAndAlgorithm(message, privateKeyHex, crypto.AlgorithmDilithium, nil)
}

// SignMessageWithPrivateKeyAndAlgorithm signs a message using a private key (secret key)
// directly for the requested algorithm. The secret key length is validated against the
// requested algorithm's constants, so an ML-DSA-87 secret key can never be fed to the
// pre-FIPS Dilithium routine (which would silently drop the FIPS 204 context binding).
func SignMessageWithPrivateKeyAndAlgorithm(message []byte, privateKeyHex, algorithm string, context []byte) (string, error) {
	skBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", errors.New("failed to decode private key: " + err.Error())
	}
	defer crypto.ZeroBytes(skBytes) // Zero decoded key bytes when done

	if algorithm == crypto.AlgorithmMLDSA {
		if len(skBytes) != ml_dsa_87.CRYPTO_SECRET_KEY_BYTES {
			return "", errors.New("invalid ML-DSA-87 private key length")
		}
		if context == nil {
			return "", errors.New("context is required for ML-DSA-87 (use --context flag)")
		}
		// go-qrllib currently has no public API to construct an ML-DSA-87 signer
		// from a secret key (the FIPS 204 secret key is a one-way expansion of the
		// seed, so the hexseed cannot be recovered from it). Fail closed rather
		// than silently producing a context-less Dilithium signature.
		return "", errors.New("ML-DSA-87 private key PEM signing is not supported yet; use the hexseed file (--keyfile=<name>.private.hexseed) instead")
	}

	if len(skBytes) != dilithium.CRYPTO_SECRET_KEY_BYTES {
		return "", errors.New("invalid private key length")
	}

	var sk [dilithium.CRYPTO_SECRET_KEY_BYTES]uint8
	copy(sk[:], skBytes)
	defer crypto.ZeroBytes(sk[:]) // Zero secret key array when done

	signature, err := dilithium.SignWithSecretKey(message, &sk)
	if err != nil {
		return "", errors.New("failed to sign with private key: " + err.Error())
	}

	return hex.EncodeToString(signature[:]), nil
}

// SignFile signs a file using a hexseed (Dilithium, for backward compatibility)
func SignFile(filename string, hexseed string) (string, error) {
	message, err := readFile(filename)
	if err != nil {
		return "", err
	}
	return SignMessage(message, hexseed)
}

// SignString signs a string using a hexseed (Dilithium, for backward compatibility)
func SignString(stringToSign string, hexseed string) (string, error) {
	return SignMessage([]byte(stringToSign), hexseed)
}

// SignFileWithPrivateKey signs a file using a private key directly (Dilithium, for
// backward compatibility). Use SignFileWithPrivateKeyAndAlgorithm when the requested
// algorithm is known (as the CLI does).
func SignFileWithPrivateKey(filename string, privateKeyHex string) (string, error) {
	message, err := readFile(filename)
	if err != nil {
		return "", err
	}
	return SignMessageWithPrivateKey(message, privateKeyHex)
}

// SignFileWithPrivateKeyAndAlgorithm signs a file using a private key directly
// for the requested algorithm.
func SignFileWithPrivateKeyAndAlgorithm(filename, privateKeyHex, algorithm string, context []byte) (string, error) {
	message, err := readFile(filename)
	if err != nil {
		return "", err
	}
	return SignMessageWithPrivateKeyAndAlgorithm(message, privateKeyHex, algorithm, context)
}

// SignStringWithPrivateKey signs a string using a private key directly (Dilithium, for
// backward compatibility). Use SignStringWithPrivateKeyAndAlgorithm when the requested
// algorithm is known (as the CLI does).
func SignStringWithPrivateKey(stringToSign string, privateKeyHex string) (string, error) {
	return SignMessageWithPrivateKey([]byte(stringToSign), privateKeyHex)
}

// SignStringWithPrivateKeyAndAlgorithm signs a string using a private key directly
// for the requested algorithm.
func SignStringWithPrivateKeyAndAlgorithm(stringToSign, privateKeyHex, algorithm string, context []byte) (string, error) {
	return SignMessageWithPrivateKeyAndAlgorithm([]byte(stringToSign), privateKeyHex, algorithm, context)
}

// SignMessageWithSigner signs a message using a Signer interface
func SignMessageWithSigner(message []byte, signer crypto.Signer) (string, error) {
	signature, err := signer.Sign(message)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature), nil
}

// SignFileWithSigner signs a file using a Signer interface
func SignFileWithSigner(filename string, signer crypto.Signer) (string, error) {
	message, err := readFile(filename)
	if err != nil {
		return "", err
	}
	return SignMessageWithSigner(message, signer)
}

// SignStringWithSigner signs a string using a Signer interface
func SignStringWithSigner(stringToSign string, signer crypto.Signer) (string, error) {
	return SignMessageWithSigner([]byte(stringToSign), signer)
}

// SignMessageWithAlgorithm signs a message using the specified algorithm
func SignMessageWithAlgorithm(message []byte, hexseed string, algorithm string, context []byte) (string, error) {
	signer, err := crypto.NewSigner(algorithm, hexseed, context)
	if err != nil {
		return "", err
	}
	return SignMessageWithSigner(message, signer)
}

// SignFileWithAlgorithm signs a file using the specified algorithm
func SignFileWithAlgorithm(filename string, hexseed string, algorithm string, context []byte) (string, error) {
	message, err := readFile(filename)
	if err != nil {
		return "", err
	}
	return SignMessageWithAlgorithm(message, hexseed, algorithm, context)
}

// SignStringWithAlgorithm signs a string using the specified algorithm
func SignStringWithAlgorithm(stringToSign string, hexseed string, algorithm string, context []byte) (string, error) {
	return SignMessageWithAlgorithm([]byte(stringToSign), hexseed, algorithm, context)
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
