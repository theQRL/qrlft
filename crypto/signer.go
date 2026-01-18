package crypto

// Signer defines the interface for cryptographic signing operations
type Signer interface {
	// Sign signs the message and returns the signature
	Sign(message []byte) ([]byte, error)
	// GetPK returns the public key bytes
	GetPK() []byte
	// GetSK returns the secret key bytes
	GetSK() []byte
	// GetHexSeed returns the hexadecimal seed string
	GetHexSeed() string
	// SignatureSize returns the size of signatures in bytes
	SignatureSize() int
	// PublicKeySize returns the size of public keys in bytes
	PublicKeySize() int
	// SecretKeySize returns the size of secret keys in bytes
	SecretKeySize() int
	// AlgorithmName returns the name of the algorithm
	AlgorithmName() string
}

// Verifier defines the interface for signature verification
type Verifier interface {
	// Verify verifies a signature against a message and public key
	Verify(message, signature, publicKey []byte) bool
	// SignatureSize returns the expected signature size in bytes
	SignatureSize() int
	// PublicKeySize returns the expected public key size in bytes
	PublicKeySize() int
	// AlgorithmName returns the name of the algorithm
	AlgorithmName() string
}

// Algorithm constants
const (
	AlgorithmDilithium = "dilithium"
	AlgorithmMLDSA     = "mldsa"
)

// PEM header constants
const (
	PEMDilithiumPrivateKey    = "DILITHIUM PRIVATE KEY"
	PEMDilithiumPublicKey     = "DILITHIUM PUBLIC KEY"
	PEMDilithiumPrivateHexseed = "DILITHIUM PRIVATE HEXSEED"

	PEMMLDSAPrivateKey     = "ML-DSA-87 PRIVATE KEY"
	PEMMLDSAPublicKey      = "ML-DSA-87 PUBLIC KEY"
	PEMMLDSAPrivateHexseed = "ML-DSA-87 PRIVATE HEXSEED"
)
