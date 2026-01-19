package verify

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
	"github.com/theQRL/qrlft/crypto"
	"github.com/theQRL/qrlft/sign"
)

func TestVerifyMessage(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"

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

func TestVerifyMessageInvalidSignatureHex(t *testing.T) {
	pk := strings.Repeat("ab", 2592) // Valid length PK
	_, err := VerifyMessage([]byte("test"), "not-valid-hex!", pk)
	if err == nil {
		t.Error("VerifyMessage() should return error for invalid signature hex")
	}
}

func TestVerifyMessageInvalidSignatureLength(t *testing.T) {
	pk := strings.Repeat("ab", 2592) // Valid length PK
	_, err := VerifyMessage([]byte("test"), "abcd1234", pk) // Too short
	if err == nil {
		t.Error("VerifyMessage() should return error for invalid signature length")
	}
}

func TestVerifyMessageInvalidPKHex(t *testing.T) {
	sig := strings.Repeat("ab", 4595) // Valid length signature (4595 bytes = 9190 hex chars)
	_, err := VerifyMessage([]byte("test"), sig, "not-valid-hex!")
	if err == nil {
		t.Error("VerifyMessage() should return error for invalid public key hex")
	}
}

func TestVerifyMessageInvalidPKLength(t *testing.T) {
	sig := strings.Repeat("ab", 4595) // Valid length signature
	_, err := VerifyMessage([]byte("test"), sig, "abcd1234") // Too short
	if err == nil {
		t.Error("VerifyMessage() should return error for invalid public key length")
	}
}

func TestVerifyFile(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"

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

// ==================== WithAlgorithm tests ====================

func TestVerifyMessageWithAlgorithm(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"

	// Generate public key
	d, _ := dilithium.NewDilithiumFromHexSeed(hexseed)
	pkBin := d.GetPK()
	pk := hex.EncodeToString(pkBin[:])

	// Sign
	signature, _ := sign.SignString("test", hexseed)

	// Verify with algorithm
	verified, err := VerifyMessageWithAlgorithm([]byte("test"), signature, pk, "dilithium", nil)
	if err != nil {
		t.Errorf("VerifyMessageWithAlgorithm() error = %v", err)
	}
	if !verified {
		t.Error("VerifyMessageWithAlgorithm() should return true for valid signature")
	}
}

func TestVerifyMessageWithAlgorithmInvalidAlgorithm(t *testing.T) {
	_, err := VerifyMessageWithAlgorithm([]byte("test"), "sig", "pk", "invalid", nil)
	if err == nil {
		t.Error("VerifyMessageWithAlgorithm() expected error for invalid algorithm")
	}
}

func TestVerifyFileWithAlgorithm(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"

	// Generate public key
	d, _ := dilithium.NewDilithiumFromHexSeed(hexseed)
	pkBin := d.GetPK()
	pk := hex.EncodeToString(pkBin[:])

	testFile := filepath.Join("..", "test_vectors", "ascii.txt")
	signature, _ := sign.SignFile(testFile, hexseed)

	// Verify with algorithm
	verified, err := VerifyFileWithAlgorithm(testFile, signature, pk, "dilithium", nil)
	if err != nil {
		t.Errorf("VerifyFileWithAlgorithm() error = %v", err)
	}
	if !verified {
		t.Error("VerifyFileWithAlgorithm() should return true for valid signature")
	}
}

func TestVerifyFileWithAlgorithmNonexistent(t *testing.T) {
	_, err := VerifyFileWithAlgorithm("/nonexistent/file.txt", "sig", "pk", "dilithium", nil)
	if err == nil {
		t.Error("VerifyFileWithAlgorithm() expected error for nonexistent file")
	}
}

func TestVerifyFileWithAlgorithmInvalidAlgorithm(t *testing.T) {
	testFile := filepath.Join("..", "test_vectors", "ascii.txt")
	_, err := VerifyFileWithAlgorithm(testFile, "sig", "pk", "invalid", nil)
	if err == nil {
		t.Error("VerifyFileWithAlgorithm() expected error for invalid algorithm")
	}
}

// ==================== WithVerifier tests ====================

func TestVerifyMessageWithVerifier(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"

	// Generate public key
	d, _ := dilithium.NewDilithiumFromHexSeed(hexseed)
	pkBin := d.GetPK()
	pk := hex.EncodeToString(pkBin[:])

	// Sign
	signature, _ := sign.SignString("test", hexseed)

	// Verify with verifier
	verifier := crypto.NewDilithiumVerifier()
	verified, err := VerifyMessageWithVerifier([]byte("test"), signature, pk, verifier)
	if err != nil {
		t.Errorf("VerifyMessageWithVerifier() error = %v", err)
	}
	if !verified {
		t.Error("VerifyMessageWithVerifier() should return true for valid signature")
	}
}

func TestVerifyMessageWithVerifierInvalidSignature(t *testing.T) {
	verifier := crypto.NewDilithiumVerifier()
	_, err := VerifyMessageWithVerifier([]byte("test"), "not-valid-hex", "abcd", verifier)
	if err == nil {
		t.Error("VerifyMessageWithVerifier() expected error for invalid signature hex")
	}
}

func TestVerifyMessageWithVerifierInvalidPK(t *testing.T) {
	verifier := crypto.NewDilithiumVerifier()
	// Valid hex for sig but invalid for pk
	validSig := strings.Repeat("00", 4595) // Dilithium signature size
	_, err := VerifyMessageWithVerifier([]byte("test"), validSig, "not-valid-hex", verifier)
	if err == nil {
		t.Error("VerifyMessageWithVerifier() expected error for invalid public key hex")
	}
}

func TestVerifyFileWithVerifier(t *testing.T) {
	hexseed := "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"

	// Generate public key
	d, _ := dilithium.NewDilithiumFromHexSeed(hexseed)
	pkBin := d.GetPK()
	pk := hex.EncodeToString(pkBin[:])

	testFile := filepath.Join("..", "test_vectors", "ascii.txt")
	signature, _ := sign.SignFile(testFile, hexseed)

	// Verify with verifier
	verifier := crypto.NewDilithiumVerifier()
	verified, err := VerifyFileWithVerifier(testFile, signature, pk, verifier)
	if err != nil {
		t.Errorf("VerifyFileWithVerifier() error = %v", err)
	}
	if !verified {
		t.Error("VerifyFileWithVerifier() should return true for valid signature")
	}
}

func TestVerifyFileWithVerifierNonexistent(t *testing.T) {
	verifier := crypto.NewDilithiumVerifier()
	_, err := VerifyFileWithVerifier("/nonexistent/file.txt", "sig", "pk", verifier)
	if err == nil {
		t.Error("VerifyFileWithVerifier() expected error for nonexistent file")
	}
}

// ==================== Error path tests ====================

func TestVerifyFileNonexistent(t *testing.T) {
	_, err := VerifyFile("/nonexistent/file.txt", "sig", "pk")
	if err == nil {
		t.Error("VerifyFile() expected error for nonexistent file")
	}
}

func TestVerifyFileDirectory(t *testing.T) {
	tempDir := t.TempDir()
	_, err := VerifyFile(tempDir, "sig", "pk")
	if err == nil {
		t.Error("VerifyFile() expected error for directory")
	}
}

func TestPKHStrToBinInvalidLength(t *testing.T) {
	_, err := PKHStrToBin("short")
	if err == nil {
		t.Error("PKHStrToBin() should return error for invalid length")
	}
}

func TestPKHStrToBinInvalidHex(t *testing.T) {
	// Create a string of correct length but invalid hex
	invalidHex := strings.Repeat("zz", 2592) // 2592 bytes = 5184 hex chars
	_, err := PKHStrToBin(invalidHex)
	if err == nil {
		t.Error("PKHStrToBin() should return error for invalid hex")
	}
}

func TestPKHStrToBinValid(t *testing.T) {
	// Create a valid hex string of correct length
	validHex := strings.Repeat("ab", 2592) // 2592 bytes = 5184 hex chars
	pk, err := PKHStrToBin(validHex)
	if err != nil {
		t.Errorf("PKHStrToBin() unexpected error: %v", err)
	}
	if len(pk) != 2592 {
		t.Errorf("PKHStrToBin() returned wrong length: got %d, want 2592", len(pk))
	}
}

// ==================== MLDSA tests ====================

func TestVerifyMLDSA(t *testing.T) {
	hexseed := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	context := []byte("test-context")

	// Create signer and get public key
	signer, _ := crypto.NewSigner("mldsa", hexseed, context)
	pk := hex.EncodeToString(signer.GetPK())

	// Sign
	sig, _ := signer.Sign([]byte("test message"))
	signature := hex.EncodeToString(sig)

	// Verify with algorithm
	verified, err := VerifyMessageWithAlgorithm([]byte("test message"), signature, pk, "mldsa", context)
	if err != nil {
		t.Errorf("VerifyMessageWithAlgorithm(mldsa) error = %v", err)
	}
	if !verified {
		t.Error("VerifyMessageWithAlgorithm(mldsa) should return true for valid signature")
	}
}

func TestVerifyMLDSAWrongContext(t *testing.T) {
	hexseed := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	context := []byte("test-context")
	wrongContext := []byte("wrong-context")

	// Create signer and get public key
	signer, _ := crypto.NewSigner("mldsa", hexseed, context)
	pk := hex.EncodeToString(signer.GetPK())

	// Sign with correct context
	sig, _ := signer.Sign([]byte("test message"))
	signature := hex.EncodeToString(sig)

	// Verify with wrong context
	verified, err := VerifyMessageWithAlgorithm([]byte("test message"), signature, pk, "mldsa", wrongContext)
	if err != nil {
		t.Errorf("VerifyMessageWithAlgorithm(mldsa) error = %v", err)
	}
	if verified {
		t.Error("VerifyMessageWithAlgorithm(mldsa) should return false for wrong context")
	}
}
