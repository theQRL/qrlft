package verify

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/theQRL/qrlft/sign"
)

func TestVerifyMessage(t *testing.T) {
	hexseed := "a3c0d45de8b5053d44888d6cc9a8690db5c9296ade4f524f252de893477ff849c11a95e8a9477297634064f207500d14"
	pkBytes, err := os.ReadFile("../newJP.pub")
	if err != nil {
		t.Errorf("ReadFile() error = %v", err)
	}
	pk := string(pkBytes)
	pk = pk[36 : len(pk)-35]
	pk = strings.ReplaceAll(pk, "\n", "")
	pkBytes, err = base64.StdEncoding.DecodeString(pk)
	if err != nil {
		t.Errorf("DecodeString() error = %v", err)
	}
	pk = hex.EncodeToString(pkBytes)

	signature, err := sign.SignString("test", hexseed)
	if err != nil {
		t.Errorf("SignString() error = %v", err)
	}

	verified, err := VerifyMessage([]byte("test"), signature, pk)
	if err != nil {
		t.Errorf("VerifyMessage() error = %v", err)
	}

	if !verified {
		t.Errorf("VerifyMessage() = %v, want %v", verified, true)
	}
}

func TestVerifyFile(t *testing.T) {
	hexseed := "a3c0d45de8b5053d44888d6cc9a8690db5c9296ade4f524f252de893477ff849c11a95e8a9477297634064f207500d14"
	pkBytes, err := os.ReadFile("../newJP.pub")
	if err != nil {
		t.Errorf("ReadFile() error = %v", err)
	}
	pk := string(pkBytes)
	pk = pk[36 : len(pk)-35]
	pk = strings.ReplaceAll(pk, "\n", "")
	pkBytes, err = base64.StdEncoding.DecodeString(pk)
	if err != nil {
		t.Errorf("DecodeString() error = %v", err)
	}
	pk = hex.EncodeToString(pkBytes)

	// create a test file
	f, err := os.Create("test.txt")
	if err != nil {
		t.Errorf("Create() error = %v", err)
	}
	defer os.Remove("test.txt")

	_, err = f.WriteString("test")
	if err != nil {
		t.Errorf("WriteString() error = %v", err)
	}

	signature, err := sign.SignFile("test.txt", hexseed)
	if err != nil {
		t.Errorf("SignFile() error = %v", err)
	}

	verified, err := VerifyFile("test.txt", signature, pk)
	if err != nil {
		t.Errorf("VerifyFile() error = %v", err)
	}

	if !verified {
		t.Errorf("VerifyFile() = %v, want %v", verified, true)
	}
}
