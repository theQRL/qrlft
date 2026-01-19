package hash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ==================== Reader-based tests ====================

func TestKeccak256Reader(t *testing.T) {
	reader := strings.NewReader("test")
	hash, err := Keccak256Reader(reader)
	if err != nil {
		t.Errorf("Keccak256Reader() error = %v", err)
	}
	if hash != "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658" {
		t.Errorf("Keccak256Reader() = %v, want %v", hash, "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
	}
}

func TestKeccak512Reader(t *testing.T) {
	reader := strings.NewReader("test")
	hash, err := Keccak512Reader(reader)
	if err != nil {
		t.Errorf("Keccak512Reader() error = %v", err)
	}
	if hash != "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e" {
		t.Errorf("Keccak512Reader() = %v, want %v", hash, "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e")
	}
}

func TestSHA3512Reader(t *testing.T) {
	reader := strings.NewReader("test")
	hash, err := SHA3512Reader(reader)
	if err != nil {
		t.Errorf("SHA3512Reader() error = %v", err)
	}
	if hash != "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14" {
		t.Errorf("SHA3512Reader() = %v, want %v", hash, "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14")
	}
}

func TestSHA256sumReader(t *testing.T) {
	reader := strings.NewReader("test")
	hash, err := SHA256sumReader(reader)
	if err != nil {
		t.Errorf("SHA256sumReader() error = %v", err)
	}
	if hash != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Errorf("SHA256sumReader() = %v, want %v", hash, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	}
}

func TestBlake2s256Reader(t *testing.T) {
	reader := strings.NewReader("test")
	hash, err := Blake2s256Reader(reader)
	if err != nil {
		t.Errorf("Blake2s256Reader() error = %v", err)
	}
	if hash != "f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e" {
		t.Errorf("Blake2s256Reader() = %v, want %v", hash, "f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e")
	}
}

// ==================== File-based tests ====================

func createTestFile(t *testing.T, content string) string {
	t.Helper()
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	return testFile
}

func TestKeccak256sum(t *testing.T) {
	testFile := createTestFile(t, "test")
	hash, err := Keccak256sum(testFile)
	if err != nil {
		t.Errorf("Keccak256sum() error = %v", err)
	}
	if hash != "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658" {
		t.Errorf("Keccak256sum() = %v, want %v", hash, "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
	}
}

func TestKeccak256sumNonexistent(t *testing.T) {
	_, err := Keccak256sum("/nonexistent/file.txt")
	if err == nil {
		t.Error("Keccak256sum() expected error for nonexistent file")
	}
}

func TestKeccak256sumDirectory(t *testing.T) {
	tempDir := t.TempDir()
	_, err := Keccak256sum(tempDir)
	if err == nil {
		t.Error("Keccak256sum() expected error for directory")
	}
}

func TestKeccak512sum(t *testing.T) {
	testFile := createTestFile(t, "test")
	hash, err := Keccak512sum(testFile)
	if err != nil {
		t.Errorf("Keccak512sum() error = %v", err)
	}
	if hash != "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e" {
		t.Errorf("Keccak512sum() = %v, want %v", hash, "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e")
	}
}

func TestSHA3512sum(t *testing.T) {
	testFile := createTestFile(t, "test")
	hash, err := SHA3512sum(testFile)
	if err != nil {
		t.Errorf("SHA3512sum() error = %v", err)
	}
	if hash != "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14" {
		t.Errorf("SHA3512sum() = %v, want %v", hash, "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14")
	}
}

func TestSHA256sum(t *testing.T) {
	testFile := createTestFile(t, "test")
	hash, err := SHA256sum(testFile)
	if err != nil {
		t.Errorf("SHA256sum() error = %v", err)
	}
	if hash != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Errorf("SHA256sum() = %v, want %v", hash, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	}
}

func TestBlake2s256(t *testing.T) {
	testFile := createTestFile(t, "test")
	hash, err := Blake2s256(testFile)
	if err != nil {
		t.Errorf("Blake2s256() error = %v", err)
	}
	if hash != "f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e" {
		t.Errorf("Blake2s256() = %v, want %v", hash, "f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e")
	}
}

// ==================== String-based tests ====================

func TestSHA3512string(t *testing.T) {
	hash := SHA3512string("test")
	expected := "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14"
	if hash != expected {
		t.Errorf("SHA3512string() = %v, want %v", hash, expected)
	}
}

func TestSHA256string(t *testing.T) {
	hash := SHA256string("test")
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if hash != expected {
		t.Errorf("SHA256string() = %v, want %v", hash, expected)
	}
}

func TestKeccak256string(t *testing.T) {
	hash := Keccak256string("test")
	expected := "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658"
	if hash != expected {
		t.Errorf("Keccak256string() = %v, want %v", hash, expected)
	}
}

func TestKeccak512string(t *testing.T) {
	hash := Keccak512string("test")
	expected := "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e"
	if hash != expected {
		t.Errorf("Keccak512string() = %v, want %v", hash, expected)
	}
}

func TestBlake2s256string(t *testing.T) {
	hash := Blake2s256string("test")
	expected := "f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e"
	if hash != expected {
		t.Errorf("Blake2s256string() = %v, want %v", hash, expected)
	}
}

// ==================== Consistency tests ====================

func TestReaderAndFileConsistency(t *testing.T) {
	content := "test content for consistency check"
	testFile := createTestFile(t, content)

	// Hash via file
	fileHash, err := SHA3512sum(testFile)
	if err != nil {
		t.Fatalf("SHA3512sum() error = %v", err)
	}

	// Hash via reader
	readerHash, err := SHA3512Reader(strings.NewReader(content))
	if err != nil {
		t.Fatalf("SHA3512Reader() error = %v", err)
	}

	if fileHash != readerHash {
		t.Errorf("File and reader hashes don't match: file=%s, reader=%s", fileHash, readerHash)
	}
}

func TestReaderAndStringConsistency(t *testing.T) {
	content := "test content"

	// Hash via string function
	stringHash := SHA3512string(content)

	// Hash via reader
	readerHash, _ := SHA3512Reader(strings.NewReader(content))

	if stringHash != readerHash {
		t.Errorf("String and reader hashes don't match: string=%s, reader=%s", stringHash, readerHash)
	}
}

// ==================== Edge case tests ====================

func TestEmptyString(t *testing.T) {
	// Empty string should still produce valid hashes
	hash := SHA3512string("")
	if len(hash) != 128 { // SHA3-512 produces 64 bytes = 128 hex chars
		t.Errorf("SHA3512string(\"\") produced wrong length: %d", len(hash))
	}
}

func TestEmptyFile(t *testing.T) {
	testFile := createTestFile(t, "")
	hash, err := SHA3512sum(testFile)
	if err != nil {
		t.Errorf("SHA3512sum() error on empty file = %v", err)
	}
	if len(hash) != 128 {
		t.Errorf("SHA3512sum() on empty file produced wrong length: %d", len(hash))
	}
}

func TestLargeContent(t *testing.T) {
	// Test with content larger than the buffer size (65536)
	largeContent := strings.Repeat("x", 100000)
	testFile := createTestFile(t, largeContent)

	hash, err := SHA256sum(testFile)
	if err != nil {
		t.Errorf("SHA256sum() error on large file = %v", err)
	}
	if len(hash) != 64 { // SHA256 produces 32 bytes = 64 hex chars
		t.Errorf("SHA256sum() on large file produced wrong length: %d", len(hash))
	}
}
