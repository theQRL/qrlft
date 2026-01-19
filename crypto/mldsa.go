package crypto

import (
	"errors"

	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
)

// MLDSASigner implements the Signer interface for ML-DSA-87
type MLDSASigner struct {
	d   *ml_dsa_87.MLDSA87
	ctx []byte
}

// NewMLDSASigner creates a new ML-DSA-87 signer from a hexseed with context
func NewMLDSASigner(hexseed string, ctx []byte) (*MLDSASigner, error) {
	if len(ctx) > 255 {
		return nil, errors.New("context must be 0-255 bytes")
	}
	d, err := ml_dsa_87.NewMLDSA87FromHexSeed(hexseed)
	if err != nil {
		return nil, err
	}
	// Make a defensive copy of context to prevent caller modifications
	ctxCopy := make([]byte, len(ctx))
	copy(ctxCopy, ctx)
	return &MLDSASigner{d: d, ctx: ctxCopy}, nil
}

// NewMLDSAKeypair generates a new ML-DSA-87 keypair with context
func NewMLDSAKeypair(ctx []byte) (*MLDSASigner, error) {
	if len(ctx) > 255 {
		return nil, errors.New("context must be 0-255 bytes")
	}
	d, err := ml_dsa_87.New()
	if err != nil {
		return nil, err
	}
	// Make a defensive copy of context to prevent caller modifications
	ctxCopy := make([]byte, len(ctx))
	copy(ctxCopy, ctx)
	return &MLDSASigner{d: d, ctx: ctxCopy}, nil
}

// Sign signs the message using the stored context and returns the signature bytes
func (s *MLDSASigner) Sign(message []byte) ([]byte, error) {
	if s.d == nil {
		return nil, errors.New("signer not initialized")
	}
	sig, err := s.d.Sign(s.ctx, message)
	if err != nil {
		return nil, err
	}
	return sig[:], nil
}

// GetPK returns the public key bytes
func (s *MLDSASigner) GetPK() []byte {
	if s.d == nil {
		return nil
	}
	pk := s.d.GetPK()
	return pk[:]
}

// GetSK returns the secret key bytes
func (s *MLDSASigner) GetSK() []byte {
	if s.d == nil {
		return nil
	}
	sk := s.d.GetSK()
	return sk[:]
}

// GetHexSeed returns the hexadecimal seed string
func (s *MLDSASigner) GetHexSeed() string {
	if s.d == nil {
		return ""
	}
	return s.d.GetHexSeed()
}

// GetContext returns the context bytes
func (s *MLDSASigner) GetContext() []byte {
	return s.ctx
}

// SignatureSize returns the size of signatures in bytes
func (s *MLDSASigner) SignatureSize() int {
	return ml_dsa_87.CRYPTO_BYTES
}

// PublicKeySize returns the size of public keys in bytes
func (s *MLDSASigner) PublicKeySize() int {
	return ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES
}

// SecretKeySize returns the size of secret keys in bytes
func (s *MLDSASigner) SecretKeySize() int {
	return ml_dsa_87.CRYPTO_SECRET_KEY_BYTES
}

// AlgorithmName returns the name of the algorithm
func (s *MLDSASigner) AlgorithmName() string {
	return AlgorithmMLDSA
}

// MLDSAVerifier implements the Verifier interface for ML-DSA-87
type MLDSAVerifier struct {
	ctx []byte
}

// NewMLDSAVerifier creates a new ML-DSA-87 verifier with context
func NewMLDSAVerifier(ctx []byte) (*MLDSAVerifier, error) {
	if len(ctx) > 255 {
		return nil, errors.New("context must be 0-255 bytes")
	}
	// Make a defensive copy of context to prevent caller modifications
	ctxCopy := make([]byte, len(ctx))
	copy(ctxCopy, ctx)
	return &MLDSAVerifier{ctx: ctxCopy}, nil
}

// Verify verifies an ML-DSA-87 signature using the stored context
func (v *MLDSAVerifier) Verify(message, signature, publicKey []byte) bool {
	if len(signature) != ml_dsa_87.CRYPTO_BYTES {
		return false
	}
	if len(publicKey) != ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES {
		return false
	}

	var sigArray [ml_dsa_87.CRYPTO_BYTES]uint8
	copy(sigArray[:], signature)

	var pkArray [ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES]uint8
	copy(pkArray[:], publicKey)

	return ml_dsa_87.Verify(v.ctx, message, sigArray, &pkArray)
}

// SignatureSize returns the expected signature size
func (v *MLDSAVerifier) SignatureSize() int {
	return ml_dsa_87.CRYPTO_BYTES
}

// PublicKeySize returns the expected public key size
func (v *MLDSAVerifier) PublicKeySize() int {
	return ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES
}

// AlgorithmName returns the name of the algorithm
func (v *MLDSAVerifier) AlgorithmName() string {
	return AlgorithmMLDSA
}

// GetContext returns the context bytes
func (v *MLDSAVerifier) GetContext() []byte {
	return v.ctx
}
