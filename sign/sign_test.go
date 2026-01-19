package sign

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theQRL/qrlft/crypto"
)

func TestSignString(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	signature, err := SignString("test", hexseed)
	if err != nil {
		t.Errorf("SignString() error = %v", err)
	}
	if len(signature) != 9190 {
		t.Errorf("SignString() = %v, want %v", len(signature), 9190)
	}
}

// readKeyFromFile is a test helper that mimics the main.go function
func readKeyFromFile(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

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

func TestSignWithHexseedFile(t *testing.T) {
	hexseedFile := filepath.Join("..", "test_vectors", "key.private.hexseed")
	hexseed, err := readKeyFromFile(hexseedFile)
	if err != nil {
		t.Fatalf("readKeyFromFile() error = %v", err)
	}

	message := "test message"
	signature, err := SignString(message, hexseed)
	if err != nil {
		t.Errorf("SignString() error = %v", err)
	}
	if len(signature) == 0 {
		t.Errorf("SignString() returned empty signature")
	}
}

func TestSignWithPrivateKeyFile(t *testing.T) {
	keyFile := filepath.Join("..", "test_vectors", "key")
	keyData, err := readKeyFromFile(keyFile)
	if err != nil {
		t.Fatalf("readKeyFromFile() error = %v", err)
	}

	if !strings.HasPrefix(keyData, "PRIVATEKEY:") {
		t.Fatalf("Expected PRIVATEKEY: prefix, got: %s", keyData[:20])
	}

	privateKeyHex := strings.TrimPrefix(keyData, "PRIVATEKEY:")
	message := "test message"
	signature, err := SignStringWithPrivateKey(message, privateKeyHex)
	if err != nil {
		t.Errorf("SignStringWithPrivateKey() error = %v", err)
	}
	if len(signature) == 0 {
		t.Errorf("SignStringWithPrivateKey() returned empty signature")
	}
}

func TestSignFileWithHexseed(t *testing.T) {
	hexseedFile := filepath.Join("..", "test_vectors", "key.private.hexseed")
	hexseed, err := readKeyFromFile(hexseedFile)
	if err != nil {
		t.Fatalf("readKeyFromFile() error = %v", err)
	}

	testFile := filepath.Join("..", "test_vectors", "ascii.txt")
	signature, err := SignFile(testFile, hexseed)
	if err != nil {
		t.Errorf("SignFile() error = %v", err)
	}
	if len(signature) == 0 {
		t.Errorf("SignFile() returned empty signature")
	}
}

func TestSignFileWithPrivateKey(t *testing.T) {
	keyFile := filepath.Join("..", "test_vectors", "key")
	keyData, err := readKeyFromFile(keyFile)
	if err != nil {
		t.Fatalf("readKeyFromFile() error = %v", err)
	}

	privateKeyHex := strings.TrimPrefix(keyData, "PRIVATEKEY:")
	testFile := filepath.Join("..", "test_vectors", "ascii.txt")
	signature, err := SignFileWithPrivateKey(testFile, privateKeyHex)
	if err != nil {
		t.Errorf("SignFileWithPrivateKey() error = %v", err)
	}
	if len(signature) == 0 {
		t.Errorf("SignFileWithPrivateKey() returned empty signature")
	}
}

func TestSignaturesMatch(t *testing.T) {
	// Test that signing with hexseed and private key produces the same signature
	hexseedFile := filepath.Join("..", "test_vectors", "key.private.hexseed")
	hexseed, err := readKeyFromFile(hexseedFile)
	if err != nil {
		t.Fatalf("readKeyFromFile(hexseed) error = %v", err)
	}

	keyFile := filepath.Join("..", "test_vectors", "key")
	keyData, err := readKeyFromFile(keyFile)
	if err != nil {
		t.Fatalf("readKeyFromFile(key) error = %v", err)
	}

	privateKeyHex := strings.TrimPrefix(keyData, "PRIVATEKEY:")
	testFile := filepath.Join("..", "test_vectors", "ascii.txt")

	sig1, err := SignFile(testFile, hexseed)
	if err != nil {
		t.Fatalf("SignFile() with hexseed error = %v", err)
	}

	sig2, err := SignFileWithPrivateKey(testFile, privateKeyHex)
	if err != nil {
		t.Fatalf("SignFileWithPrivateKey() error = %v", err)
	}

	if sig1 != sig2 {
		t.Errorf("Signatures don't match: hexseed signature length=%d, private key signature length=%d", len(sig1), len(sig2))
	}
}

// ==================== WithAlgorithm tests ====================

func TestSignStringWithAlgorithm(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	sig, err := SignStringWithAlgorithm("test", hexseed, "dilithium", nil)
	if err != nil {
		t.Errorf("SignStringWithAlgorithm() error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("SignStringWithAlgorithm() returned empty signature")
	}
}

func TestSignStringWithAlgorithmMLDSA(t *testing.T) {
	hexseed := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	context := []byte("test-context")
	sig, err := SignStringWithAlgorithm("test", hexseed, "mldsa", context)
	if err != nil {
		t.Errorf("SignStringWithAlgorithm(mldsa) error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("SignStringWithAlgorithm(mldsa) returned empty signature")
	}
}

func TestSignStringWithAlgorithmInvalidAlgorithm(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	_, err := SignStringWithAlgorithm("test", hexseed, "invalid", nil)
	if err == nil {
		t.Error("SignStringWithAlgorithm() expected error for invalid algorithm")
	}
}

func TestSignMessageWithAlgorithm(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	sig, err := SignMessageWithAlgorithm([]byte("test"), hexseed, "dilithium", nil)
	if err != nil {
		t.Errorf("SignMessageWithAlgorithm() error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("SignMessageWithAlgorithm() returned empty signature")
	}
}

func TestSignFileWithAlgorithm(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	testFile := filepath.Join("..", "test_vectors", "ascii.txt")
	sig, err := SignFileWithAlgorithm(testFile, hexseed, "dilithium", nil)
	if err != nil {
		t.Errorf("SignFileWithAlgorithm() error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("SignFileWithAlgorithm() returned empty signature")
	}
}

func TestSignFileWithAlgorithmNonexistent(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	_, err := SignFileWithAlgorithm("/nonexistent/file.txt", hexseed, "dilithium", nil)
	if err == nil {
		t.Error("SignFileWithAlgorithm() expected error for nonexistent file")
	}
}

// ==================== WithSigner tests ====================

func TestSignMessageWithSigner(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	signer, err := crypto.NewSigner("dilithium", hexseed, nil)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	sig, err := SignMessageWithSigner([]byte("test"), signer)
	if err != nil {
		t.Errorf("SignMessageWithSigner() error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("SignMessageWithSigner() returned empty signature")
	}
}

func TestSignFileWithSigner(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	signer, err := crypto.NewSigner("dilithium", hexseed, nil)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	testFile := filepath.Join("..", "test_vectors", "ascii.txt")
	sig, err := SignFileWithSigner(testFile, signer)
	if err != nil {
		t.Errorf("SignFileWithSigner() error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("SignFileWithSigner() returned empty signature")
	}
}

func TestSignFileWithSignerNonexistent(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	signer, _ := crypto.NewSigner("dilithium", hexseed, nil)

	_, err := SignFileWithSigner("/nonexistent/file.txt", signer)
	if err == nil {
		t.Error("SignFileWithSigner() expected error for nonexistent file")
	}
}

func TestSignStringWithSigner(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	signer, err := crypto.NewSigner("dilithium", hexseed, nil)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	sig, err := SignStringWithSigner("test", signer)
	if err != nil {
		t.Errorf("SignStringWithSigner() error = %v", err)
	}
	if len(sig) == 0 {
		t.Error("SignStringWithSigner() returned empty signature")
	}
}

// ==================== Error path tests ====================

func TestSignMessageWithPrivateKeyInvalidHex(t *testing.T) {
	_, err := SignMessageWithPrivateKey([]byte("test"), "not-valid-hex")
	if err == nil {
		t.Error("SignMessageWithPrivateKey() expected error for invalid hex")
	}
}

func TestSignMessageWithPrivateKeyWrongLength(t *testing.T) {
	_, err := SignMessageWithPrivateKey([]byte("test"), "abcd1234")
	if err == nil {
		t.Error("SignMessageWithPrivateKey() expected error for wrong length")
	}
}

func TestSignFileNonexistent(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	_, err := SignFile("/nonexistent/file.txt", hexseed)
	if err == nil {
		t.Error("SignFile() expected error for nonexistent file")
	}
}

func TestSignFileWithPrivateKeyNonexistent(t *testing.T) {
	// Create a valid private key first
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	signer, _ := crypto.NewSigner("dilithium", hexseed, nil)
	sk := signer.GetSK()
	skHex := hex.EncodeToString(sk)

	_, err := SignFileWithPrivateKey("/nonexistent/file.txt", skHex)
	if err == nil {
		t.Error("SignFileWithPrivateKey() expected error for nonexistent file")
	}
}

func TestReadFileDirectory(t *testing.T) {
	tempDir := t.TempDir()
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"
	_, err := SignFile(tempDir, hexseed)
	if err == nil {
		t.Error("SignFile() expected error for directory")
	}
}
