package crypto

import (
	"errors"
	"fmt"
)

// NewSigner creates a new Signer based on the algorithm
// For ML-DSA, context is required (can be empty but not nil for explicit empty context)
func NewSigner(algorithm, hexseed string, context []byte) (Signer, error) {
	switch algorithm {
	case AlgorithmDilithium, "":
		// Empty string defaults to Dilithium for backward compatibility
		return NewDilithiumSigner(hexseed)
	case AlgorithmMLDSA:
		if context == nil {
			return nil, errors.New("context is required for ML-DSA-87 (use empty string for empty context)")
		}
		return NewMLDSASigner(hexseed, context)
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
}

// NewKeypair creates a new keypair for the specified algorithm
func NewKeypair(algorithm string, context []byte) (Signer, error) {
	switch algorithm {
	case AlgorithmDilithium, "":
		return NewDilithiumKeypair()
	case AlgorithmMLDSA:
		if context == nil {
			return nil, errors.New("context is required for ML-DSA-87 (use empty string for empty context)")
		}
		return NewMLDSAKeypair(context)
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
}

// NewVerifier creates a new Verifier based on the algorithm
// For ML-DSA, context is required (can be empty but not nil for explicit empty context)
func NewVerifier(algorithm string, context []byte) (Verifier, error) {
	switch algorithm {
	case AlgorithmDilithium, "":
		return NewDilithiumVerifier(), nil
	case AlgorithmMLDSA:
		if context == nil {
			return nil, errors.New("context is required for ML-DSA-87 (use empty string for empty context)")
		}
		return NewMLDSAVerifier(context)
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
}

// GetPEMHeaders returns the appropriate PEM headers for the algorithm
func GetPEMHeaders(algorithm string) (privateKey, publicKey, hexseed string) {
	switch algorithm {
	case AlgorithmMLDSA:
		return PEMMLDSAPrivateKey, PEMMLDSAPublicKey, PEMMLDSAPrivateHexseed
	default:
		return PEMDilithiumPrivateKey, PEMDilithiumPublicKey, PEMDilithiumPrivateHexseed
	}
}

// DetectAlgorithmFromPEM detects the algorithm from PEM headers
// Returns the algorithm name or empty string if unknown
func DetectAlgorithmFromPEM(content string) string {
	if contains(content, "ML-DSA-87") {
		return AlgorithmMLDSA
	}
	if contains(content, "DILITHIUM") {
		return AlgorithmDilithium
	}
	return ""
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
