package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

// ==================== ZeroBytes Tests ====================

func TestZeroBytes(t *testing.T) {
	// Create a slice with non-zero data
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	// Zero the slice
	ZeroBytes(data)

	// Verify all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("ZeroBytes() did not zero byte at index %d: got %d, want 0", i, b)
		}
	}
}

func TestZeroBytesEmpty(t *testing.T) {
	// Empty slice should not panic
	data := []byte{}
	ZeroBytes(data)
}

func TestZeroBytesNil(t *testing.T) {
	// Nil slice should not panic
	var data []byte
	ZeroBytes(data)
}

// Test hexseed for Dilithium (32 bytes = 64 hex chars)
const testDilithiumHexseed = "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"

// Test hexseed for ML-DSA (32 bytes = 64 hex chars)
const testMLDSAHexseed = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

var testContext = []byte("test-context")

// ==================== Dilithium Signer Tests ====================

func TestNewDilithiumSigner(t *testing.T) {
	signer, err := NewDilithiumSigner(testDilithiumHexseed)
	if err != nil {
		t.Fatalf("NewDilithiumSigner() error = %v", err)
	}
	if signer == nil {
		t.Fatal("NewDilithiumSigner() returned nil")
	}
}

func TestNewDilithiumSignerInvalidSeed(t *testing.T) {
	_, err := NewDilithiumSigner("invalid")
	if err == nil {
		t.Error("NewDilithiumSigner() expected error for invalid seed")
	}
}

func TestNewDilithiumKeypair(t *testing.T) {
	signer, err := NewDilithiumKeypair()
	if err != nil {
		t.Fatalf("NewDilithiumKeypair() error = %v", err)
	}
	if signer == nil {
		t.Fatal("NewDilithiumKeypair() returned nil")
	}

	// Verify we can get keys
	pk := signer.GetPK()
	if len(pk) == 0 {
		t.Error("GetPK() returned empty")
	}

	sk := signer.GetSK()
	if len(sk) == 0 {
		t.Error("GetSK() returned empty")
	}

	hs := signer.GetHexSeed()
	if hs == "" {
		t.Error("GetHexSeed() returned empty")
	}
}

func TestDilithiumSignerSign(t *testing.T) {
	signer, err := NewDilithiumSigner(testDilithiumHexseed)
	if err != nil {
		t.Fatalf("NewDilithiumSigner() error = %v", err)
	}

	message := []byte("test message")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if len(sig) != signer.SignatureSize() {
		t.Errorf("Sign() signature length = %d, want %d", len(sig), signer.SignatureSize())
	}
}

func TestDilithiumSignerSignNilSigner(t *testing.T) {
	signer := &DilithiumSigner{d: nil}
	_, err := signer.Sign([]byte("test"))
	if err == nil {
		t.Error("Sign() expected error for nil signer")
	}
}

func TestDilithiumSignerGetPKNil(t *testing.T) {
	signer := &DilithiumSigner{d: nil}
	pk := signer.GetPK()
	if pk != nil {
		t.Error("GetPK() expected nil for uninitialized signer")
	}
}

func TestDilithiumSignerGetSKNil(t *testing.T) {
	signer := &DilithiumSigner{d: nil}
	sk := signer.GetSK()
	if sk != nil {
		t.Error("GetSK() expected nil for uninitialized signer")
	}
}

func TestDilithiumSignerGetHexSeedNil(t *testing.T) {
	signer := &DilithiumSigner{d: nil}
	hs := signer.GetHexSeed()
	if hs != "" {
		t.Error("GetHexSeed() expected empty for uninitialized signer")
	}
}

func TestDilithiumSignerSizes(t *testing.T) {
	signer, _ := NewDilithiumSigner(testDilithiumHexseed)

	if signer.SignatureSize() <= 0 {
		t.Error("SignatureSize() should be positive")
	}
	if signer.PublicKeySize() <= 0 {
		t.Error("PublicKeySize() should be positive")
	}
	if signer.SecretKeySize() <= 0 {
		t.Error("SecretKeySize() should be positive")
	}
}

func TestDilithiumSignerAlgorithmName(t *testing.T) {
	signer, _ := NewDilithiumSigner(testDilithiumHexseed)
	if signer.AlgorithmName() != AlgorithmDilithium {
		t.Errorf("AlgorithmName() = %s, want %s", signer.AlgorithmName(), AlgorithmDilithium)
	}
}

// ==================== Dilithium Verifier Tests ====================

func TestNewDilithiumVerifier(t *testing.T) {
	verifier := NewDilithiumVerifier()
	if verifier == nil {
		t.Fatal("NewDilithiumVerifier() returned nil")
	}
}

func TestDilithiumVerifierVerify(t *testing.T) {
	signer, _ := NewDilithiumSigner(testDilithiumHexseed)
	verifier := NewDilithiumVerifier()

	message := []byte("test message")
	sig, _ := signer.Sign(message)
	pk := signer.GetPK()

	if !verifier.Verify(message, sig, pk) {
		t.Error("Verify() should return true for valid signature")
	}
}

func TestDilithiumVerifierVerifyInvalidSignature(t *testing.T) {
	signer, _ := NewDilithiumSigner(testDilithiumHexseed)
	verifier := NewDilithiumVerifier()

	message := []byte("test message")
	sig, _ := signer.Sign(message)
	pk := signer.GetPK()

	// Corrupt signature
	sig[0] ^= 0xFF

	if verifier.Verify(message, sig, pk) {
		t.Error("Verify() should return false for invalid signature")
	}
}

func TestDilithiumVerifierVerifyWrongMessage(t *testing.T) {
	signer, _ := NewDilithiumSigner(testDilithiumHexseed)
	verifier := NewDilithiumVerifier()

	message := []byte("test message")
	sig, _ := signer.Sign(message)
	pk := signer.GetPK()

	wrongMessage := []byte("wrong message")
	if verifier.Verify(wrongMessage, sig, pk) {
		t.Error("Verify() should return false for wrong message")
	}
}

func TestDilithiumVerifierVerifyWrongSigLength(t *testing.T) {
	verifier := NewDilithiumVerifier()
	if verifier.Verify([]byte("msg"), []byte("short"), make([]byte, verifier.PublicKeySize())) {
		t.Error("Verify() should return false for wrong signature length")
	}
}

func TestDilithiumVerifierVerifyWrongPKLength(t *testing.T) {
	verifier := NewDilithiumVerifier()
	if verifier.Verify([]byte("msg"), make([]byte, verifier.SignatureSize()), []byte("short")) {
		t.Error("Verify() should return false for wrong public key length")
	}
}

func TestDilithiumVerifierSizes(t *testing.T) {
	verifier := NewDilithiumVerifier()

	if verifier.SignatureSize() <= 0 {
		t.Error("SignatureSize() should be positive")
	}
	if verifier.PublicKeySize() <= 0 {
		t.Error("PublicKeySize() should be positive")
	}
}

func TestDilithiumVerifierAlgorithmName(t *testing.T) {
	verifier := NewDilithiumVerifier()
	if verifier.AlgorithmName() != AlgorithmDilithium {
		t.Errorf("AlgorithmName() = %s, want %s", verifier.AlgorithmName(), AlgorithmDilithium)
	}
}

// ==================== SignWithDilithiumSK Tests ====================

func TestSignWithDilithiumSK(t *testing.T) {
	signer, _ := NewDilithiumSigner(testDilithiumHexseed)
	sk := signer.GetSK()
	skHex := hex.EncodeToString(sk)

	message := []byte("test message")
	sig, err := SignWithDilithiumSK(message, skHex)
	if err != nil {
		t.Fatalf("SignWithDilithiumSK() error = %v", err)
	}

	// Verify the signature
	verifier := NewDilithiumVerifier()
	pk := signer.GetPK()
	if !verifier.Verify(message, sig, pk) {
		t.Error("SignWithDilithiumSK() produced invalid signature")
	}
}

func TestSignWithDilithiumSKInvalidHex(t *testing.T) {
	_, err := SignWithDilithiumSK([]byte("test"), "not-hex")
	if err == nil {
		t.Error("SignWithDilithiumSK() expected error for invalid hex")
	}
}

func TestSignWithDilithiumSKWrongLength(t *testing.T) {
	_, err := SignWithDilithiumSK([]byte("test"), "abcd1234")
	if err == nil {
		t.Error("SignWithDilithiumSK() expected error for wrong length")
	}
}

// ==================== ML-DSA Signer Tests ====================

func TestNewMLDSASigner(t *testing.T) {
	signer, err := NewMLDSASigner(testMLDSAHexseed, testContext)
	if err != nil {
		t.Fatalf("NewMLDSASigner() error = %v", err)
	}
	if signer == nil {
		t.Fatal("NewMLDSASigner() returned nil")
	}
}

func TestNewMLDSASignerInvalidSeed(t *testing.T) {
	_, err := NewMLDSASigner("invalid", testContext)
	if err == nil {
		t.Error("NewMLDSASigner() expected error for invalid seed")
	}
}

func TestNewMLDSASignerContextTooLong(t *testing.T) {
	longContext := make([]byte, 256)
	_, err := NewMLDSASigner(testMLDSAHexseed, longContext)
	if err == nil {
		t.Error("NewMLDSASigner() expected error for context > 255 bytes")
	}
}

func TestNewMLDSAKeypair(t *testing.T) {
	signer, err := NewMLDSAKeypair(testContext)
	if err != nil {
		t.Fatalf("NewMLDSAKeypair() error = %v", err)
	}
	if signer == nil {
		t.Fatal("NewMLDSAKeypair() returned nil")
	}

	// Verify we can get keys
	pk := signer.GetPK()
	if len(pk) == 0 {
		t.Error("GetPK() returned empty")
	}

	sk := signer.GetSK()
	if len(sk) == 0 {
		t.Error("GetSK() returned empty")
	}

	hs := signer.GetHexSeed()
	if hs == "" {
		t.Error("GetHexSeed() returned empty")
	}

	ctx := signer.GetContext()
	if string(ctx) != string(testContext) {
		t.Error("GetContext() returned wrong context")
	}
}

func TestNewMLDSAKeypairContextTooLong(t *testing.T) {
	longContext := make([]byte, 256)
	_, err := NewMLDSAKeypair(longContext)
	if err == nil {
		t.Error("NewMLDSAKeypair() expected error for context > 255 bytes")
	}
}

func TestMLDSASignerSign(t *testing.T) {
	signer, err := NewMLDSASigner(testMLDSAHexseed, testContext)
	if err != nil {
		t.Fatalf("NewMLDSASigner() error = %v", err)
	}

	message := []byte("test message")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if len(sig) != signer.SignatureSize() {
		t.Errorf("Sign() signature length = %d, want %d", len(sig), signer.SignatureSize())
	}
}

func TestMLDSASignerSignNilSigner(t *testing.T) {
	signer := &MLDSASigner{d: nil, ctx: testContext}
	_, err := signer.Sign([]byte("test"))
	if err == nil {
		t.Error("Sign() expected error for nil signer")
	}
}

func TestMLDSASignerGetPKNil(t *testing.T) {
	signer := &MLDSASigner{d: nil}
	pk := signer.GetPK()
	if pk != nil {
		t.Error("GetPK() expected nil for uninitialized signer")
	}
}

func TestMLDSASignerGetSKNil(t *testing.T) {
	signer := &MLDSASigner{d: nil}
	sk := signer.GetSK()
	if sk != nil {
		t.Error("GetSK() expected nil for uninitialized signer")
	}
}

func TestMLDSASignerGetHexSeedNil(t *testing.T) {
	signer := &MLDSASigner{d: nil}
	hs := signer.GetHexSeed()
	if hs != "" {
		t.Error("GetHexSeed() expected empty for uninitialized signer")
	}
}

func TestMLDSASignerSizes(t *testing.T) {
	signer, _ := NewMLDSASigner(testMLDSAHexseed, testContext)

	if signer.SignatureSize() <= 0 {
		t.Error("SignatureSize() should be positive")
	}
	if signer.PublicKeySize() <= 0 {
		t.Error("PublicKeySize() should be positive")
	}
	if signer.SecretKeySize() <= 0 {
		t.Error("SecretKeySize() should be positive")
	}
}

func TestMLDSASignerAlgorithmName(t *testing.T) {
	signer, _ := NewMLDSASigner(testMLDSAHexseed, testContext)
	if signer.AlgorithmName() != AlgorithmMLDSA {
		t.Errorf("AlgorithmName() = %s, want %s", signer.AlgorithmName(), AlgorithmMLDSA)
	}
}

// ==================== ML-DSA Verifier Tests ====================

func TestNewMLDSAVerifier(t *testing.T) {
	verifier, err := NewMLDSAVerifier(testContext)
	if err != nil {
		t.Fatalf("NewMLDSAVerifier() error = %v", err)
	}
	if verifier == nil {
		t.Fatal("NewMLDSAVerifier() returned nil")
	}
}

func TestNewMLDSAVerifierContextTooLong(t *testing.T) {
	longContext := make([]byte, 256)
	_, err := NewMLDSAVerifier(longContext)
	if err == nil {
		t.Error("NewMLDSAVerifier() expected error for context > 255 bytes")
	}
}

func TestMLDSAVerifierVerify(t *testing.T) {
	signer, _ := NewMLDSASigner(testMLDSAHexseed, testContext)
	verifier, _ := NewMLDSAVerifier(testContext)

	message := []byte("test message")
	sig, _ := signer.Sign(message)
	pk := signer.GetPK()

	if !verifier.Verify(message, sig, pk) {
		t.Error("Verify() should return true for valid signature")
	}
}

func TestMLDSAVerifierVerifyWrongContext(t *testing.T) {
	signer, _ := NewMLDSASigner(testMLDSAHexseed, testContext)
	verifier, _ := NewMLDSAVerifier([]byte("wrong-context"))

	message := []byte("test message")
	sig, _ := signer.Sign(message)
	pk := signer.GetPK()

	if verifier.Verify(message, sig, pk) {
		t.Error("Verify() should return false for wrong context")
	}
}

func TestMLDSAVerifierVerifyInvalidSignature(t *testing.T) {
	signer, _ := NewMLDSASigner(testMLDSAHexseed, testContext)
	verifier, _ := NewMLDSAVerifier(testContext)

	message := []byte("test message")
	sig, _ := signer.Sign(message)
	pk := signer.GetPK()

	// Corrupt signature
	sig[0] ^= 0xFF

	if verifier.Verify(message, sig, pk) {
		t.Error("Verify() should return false for invalid signature")
	}
}

func TestMLDSAVerifierVerifyWrongSigLength(t *testing.T) {
	verifier, _ := NewMLDSAVerifier(testContext)
	if verifier.Verify([]byte("msg"), []byte("short"), make([]byte, verifier.PublicKeySize())) {
		t.Error("Verify() should return false for wrong signature length")
	}
}

func TestMLDSAVerifierVerifyWrongPKLength(t *testing.T) {
	verifier, _ := NewMLDSAVerifier(testContext)
	if verifier.Verify([]byte("msg"), make([]byte, verifier.SignatureSize()), []byte("short")) {
		t.Error("Verify() should return false for wrong public key length")
	}
}

func TestMLDSAVerifierSizes(t *testing.T) {
	verifier, _ := NewMLDSAVerifier(testContext)

	if verifier.SignatureSize() <= 0 {
		t.Error("SignatureSize() should be positive")
	}
	if verifier.PublicKeySize() <= 0 {
		t.Error("PublicKeySize() should be positive")
	}
}

func TestMLDSAVerifierAlgorithmName(t *testing.T) {
	verifier, _ := NewMLDSAVerifier(testContext)
	if verifier.AlgorithmName() != AlgorithmMLDSA {
		t.Errorf("AlgorithmName() = %s, want %s", verifier.AlgorithmName(), AlgorithmMLDSA)
	}
}

func TestMLDSAVerifierGetContext(t *testing.T) {
	verifier, _ := NewMLDSAVerifier(testContext)
	if string(verifier.GetContext()) != string(testContext) {
		t.Error("GetContext() returned wrong context")
	}
}

func TestMLDSASignerContextDefensiveCopy(t *testing.T) {
	// Verify that modifying the original context doesn't affect the signer
	ctx := []byte("original-context")
	signer, err := NewMLDSASigner(testMLDSAHexseed, ctx)
	if err != nil {
		t.Fatalf("NewMLDSASigner() error = %v", err)
	}

	// Modify the original context
	ctx[0] = 'X'

	// Verify the signer's context is unchanged
	storedCtx := signer.GetContext()
	if storedCtx[0] == 'X' {
		t.Error("Modifying original context affected signer - defensive copy not working")
	}
	if string(storedCtx) != "original-context" {
		t.Errorf("Signer context = %s, want 'original-context'", string(storedCtx))
	}
}

func TestMLDSAVerifierContextDefensiveCopy(t *testing.T) {
	// Verify that modifying the original context doesn't affect the verifier
	ctx := []byte("original-context")
	verifier, err := NewMLDSAVerifier(ctx)
	if err != nil {
		t.Fatalf("NewMLDSAVerifier() error = %v", err)
	}

	// Modify the original context
	ctx[0] = 'X'

	// Verify the verifier's context is unchanged
	storedCtx := verifier.GetContext()
	if storedCtx[0] == 'X' {
		t.Error("Modifying original context affected verifier - defensive copy not working")
	}
	if string(storedCtx) != "original-context" {
		t.Errorf("Verifier context = %s, want 'original-context'", string(storedCtx))
	}
}

// ==================== Factory Tests ====================

func TestNewSignerDilithium(t *testing.T) {
	signer, err := NewSigner(AlgorithmDilithium, testDilithiumHexseed, nil)
	if err != nil {
		t.Fatalf("NewSigner(dilithium) error = %v", err)
	}
	if signer.AlgorithmName() != AlgorithmDilithium {
		t.Error("NewSigner(dilithium) returned wrong algorithm")
	}
}

func TestNewSignerMLDSA(t *testing.T) {
	signer, err := NewSigner(AlgorithmMLDSA, testMLDSAHexseed, testContext)
	if err != nil {
		t.Fatalf("NewSigner(mldsa) error = %v", err)
	}
	if signer.AlgorithmName() != AlgorithmMLDSA {
		t.Error("NewSigner(mldsa) returned wrong algorithm")
	}
}

func TestNewSignerMLDSANilContext(t *testing.T) {
	_, err := NewSigner(AlgorithmMLDSA, testMLDSAHexseed, nil)
	if err == nil {
		t.Error("NewSigner(mldsa) expected error for nil context")
	}
}

func TestNewSignerUnknownAlgorithm(t *testing.T) {
	_, err := NewSigner("unknown", testDilithiumHexseed, nil)
	if err == nil {
		t.Error("NewSigner(unknown) expected error")
	}
}

func TestNewKeypairDilithium(t *testing.T) {
	signer, err := NewKeypair(AlgorithmDilithium, nil)
	if err != nil {
		t.Fatalf("NewKeypair(dilithium) error = %v", err)
	}
	if signer.AlgorithmName() != AlgorithmDilithium {
		t.Error("NewKeypair(dilithium) returned wrong algorithm")
	}
}

func TestNewKeypairMLDSA(t *testing.T) {
	signer, err := NewKeypair(AlgorithmMLDSA, testContext)
	if err != nil {
		t.Fatalf("NewKeypair(mldsa) error = %v", err)
	}
	if signer.AlgorithmName() != AlgorithmMLDSA {
		t.Error("NewKeypair(mldsa) returned wrong algorithm")
	}
}

func TestNewKeypairMLDSANilContext(t *testing.T) {
	_, err := NewKeypair(AlgorithmMLDSA, nil)
	if err == nil {
		t.Error("NewKeypair(mldsa) expected error for nil context")
	}
}

func TestNewKeypairUnknownAlgorithm(t *testing.T) {
	_, err := NewKeypair("unknown", nil)
	if err == nil {
		t.Error("NewKeypair(unknown) expected error")
	}
}

func TestNewVerifierDilithium(t *testing.T) {
	verifier, err := NewVerifier(AlgorithmDilithium, nil)
	if err != nil {
		t.Fatalf("NewVerifier(dilithium) error = %v", err)
	}
	if verifier.AlgorithmName() != AlgorithmDilithium {
		t.Error("NewVerifier(dilithium) returned wrong algorithm")
	}
}

func TestNewVerifierMLDSA(t *testing.T) {
	verifier, err := NewVerifier(AlgorithmMLDSA, testContext)
	if err != nil {
		t.Fatalf("NewVerifier(mldsa) error = %v", err)
	}
	if verifier.AlgorithmName() != AlgorithmMLDSA {
		t.Error("NewVerifier(mldsa) returned wrong algorithm")
	}
}

func TestNewVerifierMLDSANilContext(t *testing.T) {
	_, err := NewVerifier(AlgorithmMLDSA, nil)
	if err == nil {
		t.Error("NewVerifier(mldsa) expected error for nil context")
	}
}

func TestNewVerifierUnknownAlgorithm(t *testing.T) {
	_, err := NewVerifier("unknown", nil)
	if err == nil {
		t.Error("NewVerifier(unknown) expected error")
	}
}

// ==================== GetPEMHeaders Tests ====================

func TestGetPEMHeadersDilithium(t *testing.T) {
	sk, pk, hs := GetPEMHeaders(AlgorithmDilithium)
	if sk != PEMDilithiumPrivateKey {
		t.Errorf("GetPEMHeaders(dilithium) sk = %s, want %s", sk, PEMDilithiumPrivateKey)
	}
	if pk != PEMDilithiumPublicKey {
		t.Errorf("GetPEMHeaders(dilithium) pk = %s, want %s", pk, PEMDilithiumPublicKey)
	}
	if hs != PEMDilithiumPrivateHexseed {
		t.Errorf("GetPEMHeaders(dilithium) hs = %s, want %s", hs, PEMDilithiumPrivateHexseed)
	}
}

func TestGetPEMHeadersMLDSA(t *testing.T) {
	sk, pk, hs := GetPEMHeaders(AlgorithmMLDSA)
	if sk != PEMMLDSAPrivateKey {
		t.Errorf("GetPEMHeaders(mldsa) sk = %s, want %s", sk, PEMMLDSAPrivateKey)
	}
	if pk != PEMMLDSAPublicKey {
		t.Errorf("GetPEMHeaders(mldsa) pk = %s, want %s", pk, PEMMLDSAPublicKey)
	}
	if hs != PEMMLDSAPrivateHexseed {
		t.Errorf("GetPEMHeaders(mldsa) hs = %s, want %s", hs, PEMMLDSAPrivateHexseed)
	}
}

func TestGetPEMHeadersDefault(t *testing.T) {
	sk, pk, hs := GetPEMHeaders("unknown")
	// Default should be Dilithium
	if sk != PEMDilithiumPrivateKey {
		t.Errorf("GetPEMHeaders(unknown) should default to dilithium")
	}
	if pk != PEMDilithiumPublicKey {
		t.Errorf("GetPEMHeaders(unknown) should default to dilithium")
	}
	if hs != PEMDilithiumPrivateHexseed {
		t.Errorf("GetPEMHeaders(unknown) should default to dilithium")
	}
}

// ==================== DetectAlgorithmFromPEM Tests ====================

func TestDetectAlgorithmFromPEMDilithium(t *testing.T) {
	content := "-----BEGIN DILITHIUM PRIVATE KEY-----\ndata\n-----END DILITHIUM PRIVATE KEY-----"
	algo := DetectAlgorithmFromPEM(content)
	if algo != AlgorithmDilithium {
		t.Errorf("DetectAlgorithmFromPEM() = %s, want %s", algo, AlgorithmDilithium)
	}
}

func TestDetectAlgorithmFromPEMMLDSA(t *testing.T) {
	content := "-----BEGIN ML-DSA-87 PRIVATE KEY-----\ndata\n-----END ML-DSA-87 PRIVATE KEY-----"
	algo := DetectAlgorithmFromPEM(content)
	if algo != AlgorithmMLDSA {
		t.Errorf("DetectAlgorithmFromPEM() = %s, want %s", algo, AlgorithmMLDSA)
	}
}

func TestDetectAlgorithmFromPEMUnknown(t *testing.T) {
	content := "-----BEGIN UNKNOWN KEY-----\ndata\n-----END UNKNOWN KEY-----"
	algo := DetectAlgorithmFromPEM(content)
	if algo != "" {
		t.Errorf("DetectAlgorithmFromPEM() = %s, want empty", algo)
	}
}

func TestDetectAlgorithmFromPEMEmpty(t *testing.T) {
	algo := DetectAlgorithmFromPEM("")
	if algo != "" {
		t.Errorf("DetectAlgorithmFromPEM() = %s, want empty", algo)
	}
}

func TestDetectAlgorithmFromPEMIgnoresPayload(t *testing.T) {
	// Test that algorithm detection only looks at PEM headers, not the base64 payload
	// This content has "DILITHIUM" in the payload but not in the header
	content := "-----BEGIN UNKNOWN KEY-----\nRElMSVRISVVN\n-----END UNKNOWN KEY-----" // "DILITHIUM" in base64
	algo := DetectAlgorithmFromPEM(content)
	if algo != "" {
		t.Errorf("DetectAlgorithmFromPEM() should not match payload content, got %s", algo)
	}
}

func TestDetectAlgorithmFromPEMWithWhitespace(t *testing.T) {
	// Test that it handles whitespace around PEM headers
	content := "  -----BEGIN DILITHIUM PRIVATE KEY-----  \n  data  \n  -----END DILITHIUM PRIVATE KEY-----  "
	algo := DetectAlgorithmFromPEM(content)
	if algo != AlgorithmDilithium {
		t.Errorf("DetectAlgorithmFromPEM() = %s, want %s", algo, AlgorithmDilithium)
	}
}

// ==================== Integration Tests ====================

func TestDilithiumSignVerifyRoundTrip(t *testing.T) {
	// Generate keypair
	signer, err := NewKeypair(AlgorithmDilithium, nil)
	if err != nil {
		t.Fatalf("NewKeypair() error = %v", err)
	}

	// Sign message
	message := []byte("integration test message")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify with verifier
	verifier, _ := NewVerifier(AlgorithmDilithium, nil)
	if !verifier.Verify(message, sig, signer.GetPK()) {
		t.Error("Verify() should return true for valid signature")
	}
}

func TestMLDSASignVerifyRoundTrip(t *testing.T) {
	// Generate keypair
	signer, err := NewKeypair(AlgorithmMLDSA, testContext)
	if err != nil {
		t.Fatalf("NewKeypair() error = %v", err)
	}

	// Sign message
	message := []byte("integration test message")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify with verifier
	verifier, _ := NewVerifier(AlgorithmMLDSA, testContext)
	if !verifier.Verify(message, sig, signer.GetPK()) {
		t.Error("Verify() should return true for valid signature")
	}
}

func TestDilithiumReproducibleFromHexseed(t *testing.T) {
	// Create two signers from the same hexseed
	signer1, _ := NewSigner(AlgorithmDilithium, testDilithiumHexseed, nil)
	signer2, _ := NewSigner(AlgorithmDilithium, testDilithiumHexseed, nil)

	// Public keys should match
	pk1 := hex.EncodeToString(signer1.GetPK())
	pk2 := hex.EncodeToString(signer2.GetPK())
	if pk1 != pk2 {
		t.Error("Same hexseed should produce same public key")
	}

	// Signatures should match (Dilithium is deterministic)
	message := []byte("test")
	sig1, _ := signer1.Sign(message)
	sig2, _ := signer2.Sign(message)
	if hex.EncodeToString(sig1) != hex.EncodeToString(sig2) {
		t.Error("Same hexseed should produce same signature")
	}
}

func TestMLDSAReproducibleFromHexseed(t *testing.T) {
	// Create two signers from the same hexseed
	signer1, _ := NewSigner(AlgorithmMLDSA, testMLDSAHexseed, testContext)
	signer2, _ := NewSigner(AlgorithmMLDSA, testMLDSAHexseed, testContext)

	// Public keys should match
	pk1 := hex.EncodeToString(signer1.GetPK())
	pk2 := hex.EncodeToString(signer2.GetPK())
	if pk1 != pk2 {
		t.Error("Same hexseed should produce same public key")
	}
}

// Test that MLDSA public key doesn't depend on context (context is only used for signing/verification)
func TestMLDSAPublicKeyIndependentOfContext(t *testing.T) {
	ctx1 := []byte("context1")
	ctx2 := []byte("context2")

	signer1, _ := NewSigner(AlgorithmMLDSA, testMLDSAHexseed, ctx1)
	signer2, _ := NewSigner(AlgorithmMLDSA, testMLDSAHexseed, ctx2)

	pk1 := hex.EncodeToString(signer1.GetPK())
	pk2 := hex.EncodeToString(signer2.GetPK())

	if pk1 != pk2 {
		t.Error("Public key should be independent of context")
	}
}

// Test cross-verification doesn't work with wrong algorithm
func TestCrossAlgorithmVerificationFails(t *testing.T) {
	// Sign with Dilithium
	dilithiumSigner, _ := NewKeypair(AlgorithmDilithium, nil)
	message := []byte("test")
	dilithiumSig, _ := dilithiumSigner.Sign(message)

	// Try to verify with MLDSA verifier (should fail due to size mismatch)
	mldsaVerifier, _ := NewVerifier(AlgorithmMLDSA, testContext)

	// This should return false (signature/key size won't match)
	if mldsaVerifier.Verify(message, dilithiumSig, dilithiumSigner.GetPK()) {
		t.Error("Cross-algorithm verification should fail")
	}
}

// Test algorithm constants and PEM constants are consistent
func TestConstantsConsistency(t *testing.T) {
	if !strings.Contains(PEMDilithiumPrivateKey, "DILITHIUM") {
		t.Error("PEMDilithiumPrivateKey should contain DILITHIUM")
	}
	if !strings.Contains(PEMMLDSAPrivateKey, "ML-DSA") {
		t.Error("PEMMLDSAPrivateKey should contain ML-DSA")
	}
}
