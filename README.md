# qrlft - QRL File Tools

Command-line tools for quantum-resistant file signing, verification, and hashing using post-quantum cryptographic algorithms.

## Installation

```bash
go install github.com/theQRL/qrlft@latest
```

Or build from source:
```bash
git clone https://github.com/theQRL/qrlft
cd qrlft
go build
```

## Supported Algorithms

| Algorithm | Description | Context Required |
|-----------|-------------|------------------|
| `dilithium` | CRYSTALS-Dilithium (default, pre-FIPS) | No |
| `mldsa` | ML-DSA-87 (FIPS 204 standard) | Yes |

## Commands

### Generate Keypair

```bash
# Dilithium (default)
qrlft new mykey
qrlft new -a dilithium mykey
qrlft new-dilithium mykey  # alias

# ML-DSA-87 (requires context)
qrlft new -a mldsa --context="myapp" mykey
qrlft new-mldsa --context="myapp" mykey  # alias

# Print to console instead of file
qrlft new --print
```

Output files: `mykey` (private key), `mykey.pub` (public key), `mykey.private.hexseed` (hexseed)

### Sign Files

```bash
# Using hexseed file
qrlft sign --keyfile=mykey.private.hexseed document.txt

# Using hexseed directly
qrlft sign --hexseed=abc123... document.txt

# ML-DSA-87 with context
qrlft sign -a mldsa --context="myapp" --keyfile=mykey.private.hexseed document.txt

# Sign a string
qrlft sign -s --hexseed=abc123... "Hello World"

# Quiet mode (signature only)
qrlft sign --quiet --keyfile=mykey.private.hexseed document.txt
```

### Verify Signatures

```bash
# From signature file
qrlft verify --sigfile=document.sig --pkfile=mykey.pub document.txt

# From command line
qrlft verify --signature=abc123... --publickey=def456... document.txt

# ML-DSA-87 with context
qrlft verify -a mldsa --context="myapp" --sigfile=document.sig --pkfile=mykey.pub document.txt
```

### Extract Public Key

```bash
# Write to file
qrlft publickey --hexseed=abc123... mykey.pub

# Print to console
qrlft publickey --print --hexseed=abc123...

# ML-DSA-87
qrlft publickey -a mldsa --context="myapp" --hexseed=abc123... mykey.pub
```

### Hash Files

All hash algorithms are post-quantum secure.

```bash
qrlft hash --sha3-512 document.txt   # Recommended
qrlft hash --sha256 document.txt
qrlft hash --keccak-256 document.txt
qrlft hash --keccak-512 document.txt
qrlft hash --blake2s document.txt

# Hash a string
qrlft hash -s --sha3-512 "Hello World"
```

### Generate Random Salt

```bash
qrlft salt 32  # Generate 32 bytes of random salt
```

## Key File Formats

Keys are stored in PEM format:

**Dilithium:**
```
-----BEGIN DILITHIUM PRIVATE KEY-----
...base64 encoded key...
-----END DILITHIUM PRIVATE KEY-----
```

**ML-DSA-87:**
```
-----BEGIN ML-DSA-87 PRIVATE KEY-----
...base64 encoded key...
-----END ML-DSA-87 PRIVATE KEY-----
```

The algorithm is auto-detected from key file headers when using `--keyfile`.

## ML-DSA-87 Context

ML-DSA-87 (FIPS 204) requires a context parameter for domain separation:

- Context is a string of 0-255 bytes
- Must be the same for signing and verification
- Signatures created with one context won't verify with another

```bash
# Sign with context
qrlft sign -a mldsa --context="myapp-v1" --keyfile=key.hexseed doc.txt > doc.sig

# Verify with same context (succeeds)
qrlft verify -a mldsa --context="myapp-v1" --sigfile=doc.sig --pkfile=key.pub doc.txt

# Verify with different context (fails)
qrlft verify -a mldsa --context="different" --sigfile=doc.sig --pkfile=key.pub doc.txt
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / Signature valid |
| 1 | Signature invalid |
| 61-84 | Various errors (missing args, file not found, etc.) |

## Large File Handling

**Hashing** uses streaming reads (64KB buffer) and can handle files of any size with constant memory usage.

**Signing and verification** require the entire file to be loaded into memory because the underlying Dilithium/ML-DSA algorithms need the complete message. For very large files, use the hash-then-sign approach:

```bash
# 1. Hash the large file (uses streaming - constant memory)
HASH=$(qrlft hash --sha3-512 --quiet largefile.bin)

# 2. Sign the hash (small string, minimal memory)
qrlft sign -a dilithium -s --hexseed=abc123... "$HASH" > largefile.sig

# 3. Verify: hash the file and verify the signature matches
HASH=$(qrlft hash --sha3-512 --quiet largefile.bin)
# Compare with the signed hash or verify programmatically
```

This approach is standard practice for signing large files and is used by tools like GPG.

## Security Considerations

- **Private key files** are created with `0600` permissions (owner read/write only)
- **Public key files** are created with `0644` permissions (world-readable)
- **Do not expose as a service**: This is a CLI tool designed for local use. Post-quantum cryptographic operations are computationally expensive. If you need to expose signing/verification as a service, implement proper rate limiting, authentication, and resource controls
- **Context for ML-DSA-87**: Always use a unique, application-specific context string to ensure domain separation between different uses of the same key

## License

MIT
