package verify

import (
	"encoding/hex"
	"errors"
	"os"

	"github.com/theQRL/go-qrllib/dilithium"
)

func VerifyFile(filename string, signature string, pk string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close()

	fileinfo, err := file.Stat()
	if err != nil {
		return false, err
	}

	if fileinfo.IsDir() {
		return false, errors.New("file is a directory")
	}

	filesize := fileinfo.Size()

	buffer := make([]byte, filesize)

	bytesread, err := file.Read(buffer)
	if err != nil {
		return false, err
	}

	// declare 4595 length uint8 array
	var sigBytes [dilithium.CryptoBytes]uint8
	fSig, _ := hex.DecodeString(signature)
	copy(sigBytes[:], fSig)

	// convert public key to 1472 length uint8 array
	pkBytes := PKHStrToBin(pk)

	return dilithium.Verify(buffer[:bytesread], sigBytes, &pkBytes), nil
	// return true, nil
}

func PKHStrToBin(pkHStr string) [dilithium.CryptoPublicKeyBytes]uint8 {
	if len(pkHStr) != 2*dilithium.CryptoPublicKeyBytes {
		panic("Invalid pkHStr")
	}
	var pk [dilithium.CryptoPublicKeyBytes]uint8
	pkDecode, _ := hex.DecodeString(pkHStr)

	copy(pk[:], pkDecode)

	return pk
}
