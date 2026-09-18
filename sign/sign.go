package sign

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/theQRL/qrlft/v4/internal/dilithium"
	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
	"github.com/theQRL/qrlft/v4/crypto"
)

// SignMessage signs a message using a hexseed (Dilithium, for backward compatibility)
func SignMessage(message []byte, hexseed string) (string, error) {
	d, err := dilithium.NewDilithiumFromHexSeed(hexseed)
	if err != nil {
		return "", fmt.Errorf("failed to generate dilithium from seed: %w", err)
	}

	signature, err := d.Sign(message)
	if err != nil {
		//coverage:ignore reason=statistically-unreachable
		//rationale: a signer constructed from a validated seed has no deterministic go-qrllib failure
		return "", fmt.Errorf("failed to sign message: %w", err)
	}
	return hex.EncodeToString(signature[:]), nil
}

// SignMessageWithPrivateKeyAndAlgorithm signs a message using a raw private key
// for the explicitly requested algorithm.
func SignMessageWithPrivateKeyAndAlgorithm(message []byte, privateKeyHex, algorithm string, context []byte) (string, error) {
	if err := crypto.ValidateAlgorithm(algorithm); err != nil {
		return "", err
	}

	skBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", errors.New("failed to decode private key: " + err.Error())
	}
	defer crypto.ZeroBytes(skBytes) // Zero decoded key bytes when done

	if algorithm == crypto.AlgorithmMLDSA {
		if len(skBytes) != ml_dsa_87.CRYPTO_SECRET_KEY_BYTES {
			return "", errors.New("invalid ML-DSA-87 private key length")
		}
		if len(context) == 0 {
			return "", errors.New("context is required for ML-DSA-87 (use --context flag)")
		}
		// go-qrllib v0.1.5 cannot construct an ML-DSA-87 signer from an
		// expanded secret key. Signing itself only needs that key, but the
		// dependency does not expose this operation yet, so fail closed.
		return "", errors.New("ML-DSA-87 private key PEM signing is not supported yet; use the hexseed file (--keyfile=<name>.private.hexseed) instead")
	}

	if len(skBytes) != dilithium.CRYPTO_SECRET_KEY_BYTES {
		return "", errors.New("invalid Dilithium private key length")
	}

	var sk [dilithium.CRYPTO_SECRET_KEY_BYTES]uint8
	copy(sk[:], skBytes)
	defer crypto.ZeroBytes(sk[:]) // Zero secret key array when done

	signature, err := dilithium.SignWithSecretKey(message, &sk)
	if err != nil {
		//coverage:ignore reason=statistically-unreachable
		//rationale: the fixed-size key is validated and go-qrllib exposes no deterministic failure
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

// SignFileWithPrivateKeyAndAlgorithm signs a file using a raw private key for
// the explicitly requested algorithm.
func SignFileWithPrivateKeyAndAlgorithm(filename, privateKeyHex, algorithm string, context []byte) (string, error) {
	message, err := readFile(filename)
	if err != nil {
		return "", err
	}
	return SignMessageWithPrivateKeyAndAlgorithm(message, privateKeyHex, algorithm, context)
}

// SignStringWithPrivateKeyAndAlgorithm signs a string using a raw private key
// for the explicitly requested algorithm.
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
	// #nosec G304 -- the CLI is explicitly designed to sign a user-selected file.
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	fileinfo, err := file.Stat()
	if err != nil {
		//coverage:ignore reason=statistically-unreachable
		//rationale: the descriptor was just opened; failure requires an external filesystem race
		return nil, err
	}

	if fileinfo.IsDir() {
		return nil, errors.New("file is a directory")
	}

	filesize := fileinfo.Size()
	buffer := make([]byte, filesize)

	bytesread, err := file.Read(buffer)
	if err != nil {
		//coverage:ignore reason=statistically-unreachable
		//rationale: exact-size read of a statted regular file fails only under external mutation
		return nil, err
	}
	return buffer[:bytesread], nil
}
