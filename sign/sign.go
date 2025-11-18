package sign

import (
	"encoding/hex"
	"errors"
	"os"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
)

func SignMessage(message []byte, hexseed string) string {
	// fmt.Print(hex.EncodeToString(message[:]) + "\n")
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
	// Decode the private key from hex
	skBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", errors.New("failed to decode private key: " + err.Error())
	}

	// Check if the private key has the correct length
	if len(skBytes) != dilithium.CryptoSecretKeyBytes {
		return "", errors.New("invalid private key length")
	}

	// Create the secret key array
	var sk [dilithium.CryptoSecretKeyBytes]uint8
	copy(sk[:], skBytes)

	// Use the new exported function - no reflection/unsafe needed!
	signature, err := dilithium.SignWithSecretKey(message, &sk)
	if err != nil {
		return "", errors.New("failed to sign with private key: " + err.Error())
	}

	return hex.EncodeToString(signature[:]), nil
}

func SignFile(filename string, hexseed string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	fileinfo, err := file.Stat()
	if err != nil {
		return "", err
	}

	if fileinfo.IsDir() {
		return "", errors.New("file is a directory")
	}

	filesize := fileinfo.Size()
	buffer := make([]byte, filesize)

	bytesread, err := file.Read(buffer)
	if err != nil {
		return "", err
	}
	return SignMessage(buffer[:bytesread], hexseed), nil
}

func SignString(stringToSign string, hexseed string) (string, error) {
	return SignMessage([]byte(stringToSign), hexseed), nil
}

// SignFileWithPrivateKey signs a file using a private key directly
func SignFileWithPrivateKey(filename string, privateKeyHex string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	fileinfo, err := file.Stat()
	if err != nil {
		return "", err
	}

	if fileinfo.IsDir() {
		return "", errors.New("file is a directory")
	}

	filesize := fileinfo.Size()
	buffer := make([]byte, filesize)

	bytesread, err := file.Read(buffer)
	if err != nil {
		return "", err
	}
	return SignMessageWithPrivateKey(buffer[:bytesread], privateKeyHex)
}

// SignStringWithPrivateKey signs a string using a private key directly
func SignStringWithPrivateKey(stringToSign string, privateKeyHex string) (string, error) {
	return SignMessageWithPrivateKey([]byte(stringToSign), privateKeyHex)
}
