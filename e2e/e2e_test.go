package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	// Build the binary before running tests
	tempDir, err := os.MkdirTemp("", "qrlft-e2e-*")
	if err != nil {
		panic("failed to create temp dir: " + err.Error())
	}

	binaryPath = filepath.Join(tempDir, "qrlft")

	// Get the project root (parent of e2e directory)
	_, thisFile, _, ok := runtimeCaller(0)
	if !ok {
		panic("failed to get current file path")
	}
	projectRoot := filepath.Dir(filepath.Dir(thisFile))

	// Build the binary from project root
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		panic("failed to build binary: " + err.Error() + "\nOutput: " + string(output))
	}

	exitCode := m.Run()
	_ = os.RemoveAll(tempDir)
	os.Exit(exitCode)
}

// runtimeCaller wraps runtime.Caller for testability
var runtimeCaller = func(skip int) (pc uintptr, file string, line int, ok bool) {
	return runtime.Caller(skip)
}

func runCmd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, err := runCmd(t, args...)
	if err != nil {
		t.Fatalf("command failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	return stdout
}

// TestAlgorithmRequired verifies that the algorithm flag is required
func TestAlgorithmRequired(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"new without algorithm", []string{"new", "-p"}},
		{"publickey without algorithm", []string{"publickey", "--hexseed=abc123", "-p"}},
		{"sign without algorithm", []string{"sign", "--hexseed=abc123", "file.txt"}},
		{"verify without algorithm", []string{"verify", "--signature=abc", "--publickey=def", "file.txt"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stderr, err := runCmd(t, tt.args...)
			if err == nil {
				t.Fatal("expected command to fail without algorithm flag")
			}
			if !strings.Contains(stderr, "Required flag") || !strings.Contains(stderr, "algorithm") {
				t.Errorf("expected error about required algorithm flag, got: %s", stderr)
			}
		})
	}
}

// TestDilithiumKeyGeneration tests the full key generation workflow for Dilithium
func TestDilithiumKeyGeneration(t *testing.T) {
	stdout := mustRun(t, "new", "-a", "dilithium", "-p")

	// Verify output contains expected sections
	if !strings.Contains(stdout, "Private Key:") {
		t.Error("output missing Private Key section")
	}
	if !strings.Contains(stdout, "Public Key:") {
		t.Error("output missing Public Key section")
	}
	if !strings.Contains(stdout, "Hexseed:") {
		t.Error("output missing Hexseed section")
	}

	// Extract hexseed
	hexseedRe := regexp.MustCompile(`Hexseed:\s*\n(0x[0-9a-fA-F]+|[0-9a-fA-F]+)`)
	matches := hexseedRe.FindStringSubmatch(stdout)
	if len(matches) < 2 {
		t.Fatal("could not extract hexseed from output")
	}
	hexseed := strings.TrimSpace(matches[1])

	// Extract public key from new command
	pkRe := regexp.MustCompile(`Public Key:\s*\n([0-9a-fA-F]+)`)
	pkMatches := pkRe.FindStringSubmatch(stdout)
	if len(pkMatches) < 2 {
		t.Fatal("could not extract public key from output")
	}
	expectedPK := strings.TrimSpace(pkMatches[1])

	// Verify publickey command produces the same public key
	pkOutput := mustRun(t, "publickey", "--hexseed="+hexseed, "-a", "dilithium", "-p")
	actualPK := strings.TrimSpace(pkOutput)

	if actualPK != expectedPK {
		t.Errorf("public key mismatch:\nexpected: %s\ngot: %s", expectedPK[:64]+"...", actualPK[:64]+"...")
	}
}

// TestMLDSAKeyGeneration tests the full key generation workflow for ML-DSA-87
func TestMLDSAKeyGeneration(t *testing.T) {
	stdout := mustRun(t, "new", "-a", "mldsa", "--context=testcontext", "-p")

	// Verify output contains expected sections
	if !strings.Contains(stdout, "Private Key:") {
		t.Error("output missing Private Key section")
	}
	if !strings.Contains(stdout, "Public Key:") {
		t.Error("output missing Public Key section")
	}
	if !strings.Contains(stdout, "Hexseed:") {
		t.Error("output missing Hexseed section")
	}

	// Extract hexseed
	hexseedRe := regexp.MustCompile(`Hexseed:\s*\n(0x[0-9a-fA-F]+|[0-9a-fA-F]+)`)
	matches := hexseedRe.FindStringSubmatch(stdout)
	if len(matches) < 2 {
		t.Fatal("could not extract hexseed from output")
	}
	hexseed := strings.TrimSpace(matches[1])

	// Extract public key from new command
	pkRe := regexp.MustCompile(`Public Key:\s*\n([0-9a-fA-F]+)`)
	pkMatches := pkRe.FindStringSubmatch(stdout)
	if len(pkMatches) < 2 {
		t.Fatal("could not extract public key from output")
	}
	expectedPK := strings.TrimSpace(pkMatches[1])

	// Verify publickey command produces the same public key
	pkOutput := mustRun(t, "publickey", "--hexseed="+hexseed, "-a", "mldsa", "--context=testcontext", "-p")
	actualPK := strings.TrimSpace(pkOutput)

	if actualPK != expectedPK {
		t.Errorf("public key mismatch:\nexpected: %s\ngot: %s", expectedPK[:64]+"...", actualPK[:64]+"...")
	}
}

// TestMLDSARequiresContext verifies that MLDSA requires a context
func TestMLDSARequiresContext(t *testing.T) {
	_, stderr, err := runCmd(t, "new", "-a", "mldsa", "-p")
	if err == nil {
		t.Fatal("expected command to fail without context for mldsa")
	}
	if !strings.Contains(stderr, "Context is required") {
		t.Errorf("expected error about context, got: %s", stderr)
	}
}

// TestHexPrefixHandling tests that both 0x and 0X prefixes are handled
func TestHexPrefixHandling(t *testing.T) {
	// Generate a key first
	stdout := mustRun(t, "new", "-a", "dilithium", "-p")

	// Extract hexseed (may or may not have 0x prefix)
	hexseedRe := regexp.MustCompile(`Hexseed:\s*\n(0x[0-9a-fA-F]+|[0-9a-fA-F]+)`)
	matches := hexseedRe.FindStringSubmatch(stdout)
	if len(matches) < 2 {
		t.Fatal("could not extract hexseed from output")
	}
	hexseed := strings.TrimSpace(matches[1])

	// Strip any existing prefix for testing
	rawHexseed := strings.TrimPrefix(strings.TrimPrefix(hexseed, "0x"), "0X")

	// Get reference public key
	refPK := strings.TrimSpace(mustRun(t, "publickey", "--hexseed="+rawHexseed, "-a", "dilithium", "-p"))

	// Test with lowercase 0x prefix
	pk0x := strings.TrimSpace(mustRun(t, "publickey", "--hexseed=0x"+rawHexseed, "-a", "dilithium", "-p"))
	if pk0x != refPK {
		t.Error("0x prefix handling failed - public keys don't match")
	}

	// Test with uppercase 0X prefix
	pk0X := strings.TrimSpace(mustRun(t, "publickey", "--hexseed=0X"+rawHexseed, "-a", "dilithium", "-p"))
	if pk0X != refPK {
		t.Error("0X prefix handling failed - public keys don't match")
	}
}

// TestDilithiumSignVerify tests the sign and verify workflow for Dilithium
func TestDilithiumSignVerify(t *testing.T) {
	// Create a temp file to sign
	tempDir, err := os.MkdirTemp("", "qrlft-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("Hello, World!"), 0644); err != nil {
		t.Fatal(err)
	}

	// Generate a key
	stdout := mustRun(t, "new", "-a", "dilithium", "-p")

	// Extract hexseed and public key
	hexseedRe := regexp.MustCompile(`Hexseed:\s*\n(0x[0-9a-fA-F]+|[0-9a-fA-F]+)`)
	matches := hexseedRe.FindStringSubmatch(stdout)
	if len(matches) < 2 {
		t.Fatal("could not extract hexseed")
	}
	hexseed := strings.TrimSpace(matches[1])

	pkRe := regexp.MustCompile(`Public Key:\s*\n([0-9a-fA-F]+)`)
	pkMatches := pkRe.FindStringSubmatch(stdout)
	if len(pkMatches) < 2 {
		t.Fatal("could not extract public key")
	}
	publicKey := strings.TrimSpace(pkMatches[1])

	// Sign the file
	signOutput := mustRun(t, "sign", "--hexseed="+hexseed, "-a", "dilithium", "--quiet", testFile)
	signature := strings.TrimSpace(signOutput)

	if signature == "" {
		t.Fatal("signature is empty")
	}

	// Verify the signature
	verifyOutput, verifyStderr, err := runCmd(t, "verify", "--signature="+signature, "--publickey="+publicKey, "-a", "dilithium", testFile)
	if err != nil {
		t.Fatalf("verify failed: %v\nstdout: %s\nstderr: %s", err, verifyOutput, verifyStderr)
	}

	if !strings.Contains(verifyStderr, "Signature is valid") {
		t.Errorf("expected 'Signature is valid', got stdout: %s, stderr: %s", verifyOutput, verifyStderr)
	}

	// Test with wrong signature (should fail)
	wrongSig := "00" + signature[2:] // Modify first byte
	_, _, err = runCmd(t, "verify", "--signature="+wrongSig, "--publickey="+publicKey, "-a", "dilithium", testFile)
	if err == nil {
		t.Error("expected verification to fail with wrong signature")
	}
}

// TestMLDSASignVerify tests the sign and verify workflow for ML-DSA-87
func TestMLDSASignVerify(t *testing.T) {
	// Create a temp file to sign
	tempDir, err := os.MkdirTemp("", "qrlft-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("Hello, World!"), 0644); err != nil {
		t.Fatal(err)
	}

	context := "test-context-123"

	// Generate a key
	stdout := mustRun(t, "new", "-a", "mldsa", "--context="+context, "-p")

	// Extract hexseed and public key
	hexseedRe := regexp.MustCompile(`Hexseed:\s*\n(0x[0-9a-fA-F]+|[0-9a-fA-F]+)`)
	matches := hexseedRe.FindStringSubmatch(stdout)
	if len(matches) < 2 {
		t.Fatal("could not extract hexseed")
	}
	hexseed := strings.TrimSpace(matches[1])

	pkRe := regexp.MustCompile(`Public Key:\s*\n([0-9a-fA-F]+)`)
	pkMatches := pkRe.FindStringSubmatch(stdout)
	if len(pkMatches) < 2 {
		t.Fatal("could not extract public key")
	}
	publicKey := strings.TrimSpace(pkMatches[1])

	// Sign the file
	signOutput := mustRun(t, "sign", "--hexseed="+hexseed, "-a", "mldsa", "--context="+context, "--quiet", testFile)
	signature := strings.TrimSpace(signOutput)

	if signature == "" {
		t.Fatal("signature is empty")
	}

	// Verify the signature
	verifyOutput, verifyStderr, err := runCmd(t, "verify", "--signature="+signature, "--publickey="+publicKey, "-a", "mldsa", "--context="+context, testFile)
	if err != nil {
		t.Fatalf("verify failed: %v\nstdout: %s\nstderr: %s", err, verifyOutput, verifyStderr)
	}

	if !strings.Contains(verifyStderr, "Signature is valid") {
		t.Errorf("expected 'Signature is valid', got stdout: %s, stderr: %s", verifyOutput, verifyStderr)
	}

	// Test with wrong context (should fail)
	_, _, err = runCmd(t, "verify", "--signature="+signature, "--publickey="+publicKey, "-a", "mldsa", "--context=wrong-context", testFile)
	if err == nil {
		t.Error("expected verification to fail with wrong context")
	}
}

// TestStringSignVerify tests signing and verifying strings
func TestStringSignVerify(t *testing.T) {
	// Generate a key
	stdout := mustRun(t, "new", "-a", "dilithium", "-p")

	// Extract hexseed and public key
	hexseedRe := regexp.MustCompile(`Hexseed:\s*\n(0x[0-9a-fA-F]+|[0-9a-fA-F]+)`)
	matches := hexseedRe.FindStringSubmatch(stdout)
	if len(matches) < 2 {
		t.Fatal("could not extract hexseed")
	}
	hexseed := strings.TrimSpace(matches[1])

	pkRe := regexp.MustCompile(`Public Key:\s*\n([0-9a-fA-F]+)`)
	pkMatches := pkRe.FindStringSubmatch(stdout)
	if len(pkMatches) < 2 {
		t.Fatal("could not extract public key")
	}
	publicKey := strings.TrimSpace(pkMatches[1])

	testString := "Test message to sign"

	// Sign the string
	signOutput, signStderr, err := runCmd(t, "sign", "--hexseed="+hexseed, "-a", "dilithium", "-s", testString)
	if err != nil {
		t.Fatalf("sign failed: %v\nstdout: %s\nstderr: %s", err, signOutput, signStderr)
	}
	signature := strings.TrimSpace(signStderr) // cli.Exit outputs to stderr

	if signature == "" {
		t.Fatal("signature is empty")
	}

	// Create temp file with the string content for verification
	tempDir, err := os.MkdirTemp("", "qrlft-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte(testString), 0644); err != nil {
		t.Fatal(err)
	}

	// Verify the signature against the file with same content
	_, verifyStderr, err := runCmd(t, "verify", "--signature="+signature, "--publickey="+publicKey, "-a", "dilithium", testFile)
	if err != nil {
		t.Fatalf("verify failed: %v\nstderr: %s", err, verifyStderr)
	}

	if !strings.Contains(verifyStderr, "Signature is valid") {
		t.Errorf("expected 'Signature is valid', got: %s", verifyStderr)
	}
}

// TestKeyFileWorkflow tests using key files for signing
func TestKeyFileWorkflow(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "qrlft-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	keyBasePath := filepath.Join(tempDir, "testkey")
	testFile := filepath.Join(tempDir, "test.txt")

	if err := os.WriteFile(testFile, []byte("Test content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Generate key files
	_, stderr, err := runCmd(t, "new", "-a", "dilithium", keyBasePath)
	if err != nil {
		t.Fatalf("key generation failed: %v\nstderr: %s", err, stderr)
	}

	// Verify key files were created
	keyFiles := []string{
		keyBasePath,                    // private key
		keyBasePath + ".pub",           // public key
		keyBasePath + ".private.hexseed", // hexseed
	}
	for _, f := range keyFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			t.Errorf("expected key file not created: %s", f)
		}
	}

	// Sign using the private key file
	signOutput := mustRun(t, "sign", "--keyfile="+keyBasePath, "-a", "dilithium", "--quiet", testFile)
	signature := strings.TrimSpace(signOutput)

	// Verify using the public key file
	_, verifyStderr, err := runCmd(t, "verify", "--signature="+signature, "--pkfile="+keyBasePath+".pub", "-a", "dilithium", testFile)
	if err != nil {
		t.Fatalf("verify with pkfile failed: %v\nstderr: %s", err, verifyStderr)
	}

	if !strings.Contains(verifyStderr, "Signature is valid") {
		t.Errorf("expected 'Signature is valid', got: %s", verifyStderr)
	}

	// Sign using the hexseed file
	signOutput2 := mustRun(t, "sign", "--keyfile="+keyBasePath+".private.hexseed", "-a", "dilithium", "--quiet", testFile)
	signature2 := strings.TrimSpace(signOutput2)

	// Both signatures should be the same (deterministic signing)
	if signature != signature2 {
		t.Error("signatures from private key and hexseed should match")
	}
}

// TestAlgorithmMismatchDetection tests that algorithm mismatch is detected
func TestAlgorithmMismatchDetection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "qrlft-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create an MLDSA key file
	keyPath := filepath.Join(tempDir, "mldskey")
	_, _, err = runCmd(t, "new", "-a", "mldsa", "--context=test", keyPath)
	if err != nil {
		t.Fatal("failed to create mldsa key")
	}

	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Try to sign with dilithium algorithm but mldsa key file
	_, stderr, err := runCmd(t, "sign", "--keyfile="+keyPath, "-a", "dilithium", testFile)
	if err == nil {
		t.Fatal("expected algorithm mismatch error")
	}
	if !strings.Contains(stderr, "Algorithm mismatch") {
		t.Errorf("expected algorithm mismatch error, got: %s", stderr)
	}
}

// TestHashCommands tests the hash command functionality
func TestHashCommands(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "qrlft-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("Hello, World!"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		flag string
	}{
		{"sha3-512", "--sha3-512"},
		{"sha256", "--sha256"},
		{"keccak-256", "--keccak-256"},
		{"keccak-512", "--keccak-512"},
		{"blake2s", "--blake2s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout := mustRun(t, "hash", tt.flag, "--quiet", testFile)
			hash := strings.TrimSpace(stdout)
			if hash == "" {
				t.Error("hash output is empty")
			}
			// Verify it's a valid hex string
			for _, c := range hash {
				isHexDigit := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
				if !isHexDigit {
					t.Errorf("invalid character in hash output: %c", c)
					break
				}
			}
		})
	}

	// Test string hashing
	t.Run("string hash", func(t *testing.T) {
		_, stderr, err := runCmd(t, "hash", "--sha3-512", "-s", "Hello")
		if err != nil {
			t.Fatalf("string hash failed: %v", err)
		}
		hash := strings.TrimSpace(stderr)
		if hash == "" {
			t.Error("string hash output is empty")
		}
	})
}

// TestSaltGeneration tests the salt generation command
func TestSaltGeneration(t *testing.T) {
	stdout := mustRun(t, "salt", "16")

	// Should contain info message and hex output
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 {
		t.Fatal("expected at least 2 lines of output")
	}

	// Last line should be 32 hex characters (16 bytes = 32 hex chars)
	salt := strings.TrimSpace(lines[len(lines)-1])
	if len(salt) != 32 {
		t.Errorf("expected 32 hex characters for 16 byte salt, got %d", len(salt))
	}
}
