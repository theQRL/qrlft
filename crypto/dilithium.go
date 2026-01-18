package crypto

import (
	"encoding/hex"
	"errors"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
)

// DilithiumSigner implements the Signer interface for Dilithium
type DilithiumSigner struct {
	d *dilithium.Dilithium
}

// NewDilithiumSigner creates a new Dilithium signer from a hexseed
func NewDilithiumSigner(hexseed string) (*DilithiumSigner, error) {
	d, err := dilithium.NewDilithiumFromHexSeed(hexseed)
	if err != nil {
		return nil, err
	}
	return &DilithiumSigner{d: d}, nil
}

// NewDilithiumSignerFromSK creates a signer from a secret key hex string
func NewDilithiumSignerFromSK(skHex string) (*DilithiumSigner, error) {
	skBytes, err := hex.DecodeString(skHex)
	if err != nil {
		return nil, errors.New("failed to decode secret key: " + err.Error())
	}
	if len(skBytes) != dilithium.CRYPTO_SECRET_KEY_BYTES {
		return nil, errors.New("invalid secret key length")
	}
	// Create a wrapper that holds the secret key for signing
	return &DilithiumSigner{d: nil}, errors.New("DilithiumSigner from SK not fully supported - use hexseed")
}

// NewDilithiumKeypair generates a new Dilithium keypair
func NewDilithiumKeypair() (*DilithiumSigner, error) {
	d, err := dilithium.New()
	if err != nil {
		return nil, err
	}
	return &DilithiumSigner{d: d}, nil
}

// Sign signs the message and returns the signature bytes
func (s *DilithiumSigner) Sign(message []byte) ([]byte, error) {
	if s.d == nil {
		return nil, errors.New("signer not initialized")
	}
	sig, err := s.d.Sign(message)
	if err != nil {
		return nil, err
	}
	return sig[:], nil
}

// GetPK returns the public key bytes
func (s *DilithiumSigner) GetPK() []byte {
	if s.d == nil {
		return nil
	}
	pk := s.d.GetPK()
	return pk[:]
}

// GetSK returns the secret key bytes
func (s *DilithiumSigner) GetSK() []byte {
	if s.d == nil {
		return nil
	}
	sk := s.d.GetSK()
	return sk[:]
}

// GetHexSeed returns the hexadecimal seed string
func (s *DilithiumSigner) GetHexSeed() string {
	if s.d == nil {
		return ""
	}
	return s.d.GetHexSeed()
}

// SignatureSize returns the size of signatures in bytes
func (s *DilithiumSigner) SignatureSize() int {
	return dilithium.CRYPTO_BYTES
}

// PublicKeySize returns the size of public keys in bytes
func (s *DilithiumSigner) PublicKeySize() int {
	return dilithium.CRYPTO_PUBLIC_KEY_BYTES
}

// SecretKeySize returns the size of secret keys in bytes
func (s *DilithiumSigner) SecretKeySize() int {
	return dilithium.CRYPTO_SECRET_KEY_BYTES
}

// AlgorithmName returns the name of the algorithm
func (s *DilithiumSigner) AlgorithmName() string {
	return AlgorithmDilithium
}

// DilithiumVerifier implements the Verifier interface for Dilithium
type DilithiumVerifier struct{}

// NewDilithiumVerifier creates a new Dilithium verifier
func NewDilithiumVerifier() *DilithiumVerifier {
	return &DilithiumVerifier{}
}

// Verify verifies a Dilithium signature
func (v *DilithiumVerifier) Verify(message, signature, publicKey []byte) bool {
	if len(signature) != dilithium.CRYPTO_BYTES {
		return false
	}
	if len(publicKey) != dilithium.CRYPTO_PUBLIC_KEY_BYTES {
		return false
	}

	var sigArray [dilithium.CRYPTO_BYTES]uint8
	copy(sigArray[:], signature)

	var pkArray [dilithium.CRYPTO_PUBLIC_KEY_BYTES]uint8
	copy(pkArray[:], publicKey)

	return dilithium.Verify(message, sigArray, &pkArray)
}

// SignatureSize returns the expected signature size
func (v *DilithiumVerifier) SignatureSize() int {
	return dilithium.CRYPTO_BYTES
}

// PublicKeySize returns the expected public key size
func (v *DilithiumVerifier) PublicKeySize() int {
	return dilithium.CRYPTO_PUBLIC_KEY_BYTES
}

// AlgorithmName returns the name of the algorithm
func (v *DilithiumVerifier) AlgorithmName() string {
	return AlgorithmDilithium
}

// SignWithDilithiumSK signs a message using a secret key directly (for backward compatibility)
func SignWithDilithiumSK(message []byte, skHex string) ([]byte, error) {
	skBytes, err := hex.DecodeString(skHex)
	if err != nil {
		return nil, errors.New("failed to decode secret key: " + err.Error())
	}
	if len(skBytes) != dilithium.CRYPTO_SECRET_KEY_BYTES {
		return nil, errors.New("invalid secret key length")
	}

	var sk [dilithium.CRYPTO_SECRET_KEY_BYTES]uint8
	copy(sk[:], skBytes)

	sig, err := dilithium.SignWithSecretKey(message, &sk)
	if err != nil {
		return nil, err
	}
	return sig[:], nil
}
