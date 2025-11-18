package verify

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
	"github.com/theQRL/qrlft/sign"
)

func TestVerifyMessage(t *testing.T) {
	hexseed := "a3c0d45de8b5053d44888d6cc9a8690db5c9296ade4f524f252de893477ff849c11a95e8a9477297634064f207500d14"
	
	// Generate public key from hexseed
	d, err := dilithium.NewDilithiumFromHexSeed(hexseed)
	if err != nil {
		t.Fatalf("NewDilithiumFromHexSeed() error = %v", err)
	}
	pkBin := d.GetPK()
	pk := hex.EncodeToString(pkBin[:])

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
	
	// Generate public key from hexseed
	d, err := dilithium.NewDilithiumFromHexSeed(hexseed)
	if err != nil {
		t.Fatalf("NewDilithiumFromHexSeed() error = %v", err)
	}
	pkBin := d.GetPK()
	pk := hex.EncodeToString(pkBin[:])

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

// readPublicKeyFromFile reads a public key from RFC7468 format file
func readPublicKeyFromFile(filepath string) (string, error) {
	pkBytes, err := os.ReadFile(filepath)
	if err != nil {
		return "", err
	}

	content := strings.TrimSpace(string(pkBytes))
	if !strings.HasPrefix(content, "-----BEGIN DILITHIUM PUBLIC KEY-----") {
		return "", err
	}

	content = strings.TrimPrefix(content, "-----BEGIN DILITHIUM PUBLIC KEY-----")
	content = strings.TrimSuffix(content, "-----END DILITHIUM PUBLIC KEY-----")
	content = strings.TrimSpace(content)
	content = strings.ReplaceAll(content, "\n", "")

	pkBytesDecoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(pkBytesDecoded), nil
}

func TestVerifyWithTestVectorsHexseed(t *testing.T) {
	hexseedFile := filepath.Join("..", "test_vectors", "key.private.hexseed")
	hexseed, err := readKeyFromFile(hexseedFile)
	if err != nil {
		t.Fatalf("readKeyFromFile() error = %v", err)
	}

	testFile := filepath.Join("..", "test_vectors", "ascii.txt")
	signature, err := sign.SignFile(testFile, hexseed)
	if err != nil {
		t.Fatalf("SignFile() error = %v", err)
	}

	// Generate public key from hexseed
	d, err := dilithium.NewDilithiumFromHexSeed(hexseed)
	if err != nil {
		t.Fatalf("NewDilithiumFromHexSeed() error = %v", err)
	}
	pkBin := d.GetPK()
	pk := hex.EncodeToString(pkBin[:])

	verified, err := VerifyFile(testFile, signature, pk)
	if err != nil {
		t.Errorf("VerifyFile() error = %v", err)
	}

	if !verified {
		t.Errorf("VerifyFile() = %v, want %v", verified, true)
	}
}

func TestVerifyWithTestVectorsPrivateKey(t *testing.T) {
	keyFile := filepath.Join("..", "test_vectors", "key")
	keyData, err := readKeyFromFile(keyFile)
	if err != nil {
		t.Fatalf("readKeyFromFile() error = %v", err)
	}

	privateKeyHex := strings.TrimPrefix(keyData, "PRIVATEKEY:")
	testFile := filepath.Join("..", "test_vectors", "ascii.txt")
	signature, err := sign.SignFileWithPrivateKey(testFile, privateKeyHex)
	if err != nil {
		t.Fatalf("SignFileWithPrivateKey() error = %v", err)
	}

	// Read public key from file
	pkFile := filepath.Join("..", "test_vectors", "key.pub")
	pk, err := readPublicKeyFromFile(pkFile)
	if err != nil {
		t.Fatalf("readPublicKeyFromFile() error = %v", err)
	}

	verified, err := VerifyFile(testFile, signature, pk)
	if err != nil {
		t.Errorf("VerifyFile() error = %v", err)
	}

	if !verified {
		t.Errorf("VerifyFile() = %v, want %v", verified, true)
	}
}

func TestVerifyWithPublicKeyFile(t *testing.T) {
	hexseedFile := filepath.Join("..", "test_vectors", "key.private.hexseed")
	hexseed, err := readKeyFromFile(hexseedFile)
	if err != nil {
		t.Fatalf("readKeyFromFile() error = %v", err)
	}

	testFile := filepath.Join("..", "test_vectors", "ascii.txt")
	signature, err := sign.SignFile(testFile, hexseed)
	if err != nil {
		t.Fatalf("SignFile() error = %v", err)
	}

	// Read public key from RFC7468 format file
	pkFile := filepath.Join("..", "test_vectors", "key.pub")
	pk, err := readPublicKeyFromFile(pkFile)
	if err != nil {
		t.Fatalf("readPublicKeyFromFile() error = %v", err)
	}

	verified, err := VerifyFile(testFile, signature, pk)
	if err != nil {
		t.Errorf("VerifyFile() error = %v", err)
	}

	if !verified {
		t.Errorf("VerifyFile() = %v, want %v", verified, true)
	}
}

// readKeyFromFile is a test helper that mimics the main.go function
func readKeyFromFile(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	fileinfo, err := file.Stat()
	if err != nil {
		return "", err
	}
	if fileinfo.IsDir() {
		return "", err
	}

	filebuffer := make([]byte, fileinfo.Size())
	_, err = file.Read(filebuffer)
	if err != nil {
		return "", err
	}

	content := strings.TrimSpace(string(filebuffer))

	// Check if it's a hexseed file (RFC7468 format)
	if strings.HasPrefix(content, "-----BEGIN DILITHIUM PRIVATE HEXSEED-----") {
		content = strings.TrimPrefix(content, "-----BEGIN DILITHIUM PRIVATE HEXSEED-----")
		content = strings.TrimSuffix(content, "-----END DILITHIUM PRIVATE HEXSEED-----")
		content = strings.TrimSpace(content)
		content = strings.TrimPrefix(content, "0x")
		return content, nil
	}

	// Check if it's a private key file (RFC7468 format)
	if strings.HasPrefix(content, "-----BEGIN DILITHIUM PRIVATE KEY-----") {
		content = strings.TrimPrefix(content, "-----BEGIN DILITHIUM PRIVATE KEY-----")
		content = strings.TrimSuffix(content, "-----END DILITHIUM PRIVATE KEY-----")
		content = strings.TrimSpace(content)
		content = strings.ReplaceAll(content, "\n", "")

		skBytes, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return "", err
		}

		privateKeyHex := hex.EncodeToString(skBytes)
		return "PRIVATEKEY:" + privateKeyHex, nil
	}

	// Assume it's a plain hexseed string
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "0x")
	_, err = hex.DecodeString(content)
	if err != nil {
		return "", err
	}
	return content, nil
}
