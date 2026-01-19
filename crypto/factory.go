package crypto

import (
	"errors"
	"fmt"
	"strings"
)

// NewSigner creates a new Signer based on the algorithm
// For ML-DSA, context is required (can be empty but not nil for explicit empty context)
func NewSigner(algorithm, hexseed string, context []byte) (Signer, error) {
	switch algorithm {
	case AlgorithmDilithium:
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
	case AlgorithmDilithium:
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
	case AlgorithmDilithium:
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
// Only examines PEM header lines (-----BEGIN/END) to avoid false matches
// from content within the base64 payload
// Returns the algorithm name or empty string if unknown
func DetectAlgorithmFromPEM(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Only check PEM header/footer lines
		if strings.HasPrefix(line, "-----BEGIN ") || strings.HasPrefix(line, "-----END ") {
			if strings.Contains(line, "ML-DSA-87") {
				return AlgorithmMLDSA
			}
			if strings.Contains(line, "DILITHIUM") {
				return AlgorithmDilithium
			}
		}
	}
	return ""
}
