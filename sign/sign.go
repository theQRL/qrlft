package sign

import (
	"encoding/hex"
	"errors"
	"os"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
	"github.com/theQRL/qrlft/crypto"
)

// SignMessage signs a message using a hexseed (Dilithium, for backward compatibility)
func SignMessage(message []byte, hexseed string) string {
	d, err := dilithium.NewDilithiumFromHexSeed(hexseed)
	if err != nil {
		panic("failed to generate new dilithium from seed " + err.Error())
	}

	signature, err := d.Sign(message)
	if err != nil {
		panic("failed to sign " + err.Error())
	}
	return hex.EncodeToString(signature[:])
}

// SignMessageWithPrivateKey signs a message using a private key (secret key) directly
func SignMessageWithPrivateKey(message []byte, privateKeyHex string) (string, error) {
	skBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", errors.New("failed to decode private key: " + err.Error())
	}

	if len(skBytes) != dilithium.CRYPTO_SECRET_KEY_BYTES {
		return "", errors.New("invalid private key length")
	}

	var sk [dilithium.CRYPTO_SECRET_KEY_BYTES]uint8
	copy(sk[:], skBytes)

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
	return SignMessage(message, hexseed), nil
}

// SignString signs a string using a hexseed (Dilithium, for backward compatibility)
func SignString(stringToSign string, hexseed string) (string, error) {
	return SignMessage([]byte(stringToSign), hexseed), nil
}

// SignFileWithPrivateKey signs a file using a private key directly
func SignFileWithPrivateKey(filename string, privateKeyHex string) (string, error) {
	message, err := readFile(filename)
	if err != nil {
		return "", err
	}
	return SignMessageWithPrivateKey(message, privateKeyHex)
}

// SignStringWithPrivateKey signs a string using a private key directly
func SignStringWithPrivateKey(stringToSign string, privateKeyHex string) (string, error) {
	return SignMessageWithPrivateKey([]byte(stringToSign), privateKeyHex)
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
