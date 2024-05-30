package sign

import (
	"encoding/hex"
	"os"

	"github.com/theQRL/go-qrllib/dilithium"
)

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

	filesize := fileinfo.Size()
	buffer := make([]byte, filesize)

	bytesread, err := file.Read(buffer)
	if err != nil {
		return "", err
	}
	return SignMessage(buffer[:bytesread], hexseed), nil
}
