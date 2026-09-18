# qrlft - QRL File Tools

Command-line tools for quantum-resistant file signing, verification, and hashing using post-quantum cryptographic algorithms.

## Installation

### Pre-built binaries

Download the archive for your platform from the
[releases page](https://github.com/theQRL/qrlft/releases) and check it against
the published signatures (see [Verifying a Release](#verifying-a-release)).
Unzip it and move the `qrlft` binary onto your `PATH` — usually
`/usr/local/bin` on macOS and Linux, or any directory listed in `PATH` on
Windows — otherwise you have to invoke it by its full path.

### With Go

```bash
go install github.com/theQRL/qrlft/v4@latest
```

This installs into `$(go env GOPATH)/bin`, which must itself be on your `PATH`
for `qrlft` to resolve as a bare command.

### From source

```bash
git clone https://github.com/theQRL/qrlft
cd qrlft
go build
```

`go build` leaves the binary in the checkout, so either run it as `./qrlft` or
move it onto your `PATH` as above.

## Supported Algorithms

| Algorithm | Description | Context Required |
|-----------|-------------|------------------|
| `dilithium` | CRYSTALS-Dilithium (pre-FIPS) | No |
| `mldsa` | ML-DSA-87 (FIPS 204 standard) | Yes |

## Commands

### Generate Keypair

```bash
# Dilithium
qrlft new -a dilithium mykey
qrlft new-dilithium -a dilithium mykey  # alias

# ML-DSA-87 (requires context)
qrlft new -a mldsa --context="myapp" mykey
qrlft new-mldsa -a mldsa --context="myapp" mykey  # alias

# Print to console instead of file
qrlft new -a dilithium --print
```

Output files: `mykey` (private key), `mykey.pub` (public key), and
`mykey.private.hexseed` (compatibility copy of the private seed key)

ML-DSA-87 private and public keys use the standardized RFC 9881 PKCS#8 and
SubjectPublicKeyInfo encodings. Both `mykey` and the retained
`mykey.private.hexseed` compatibility filename contain the same recommended
seed-only PKCS#8 private-key representation and can be supplied to `--keyfile`.

### Sign Files

```bash
# Using hexseed file
qrlft sign -a dilithium --keyfile=mykey.private.hexseed document.txt

# Using hexseed directly
qrlft sign -a dilithium --hexseed=abc123... document.txt

# ML-DSA-87 with context and its standard private key
qrlft sign -a mldsa --context="myapp" --keyfile=mykey document.txt

# Sign a string
qrlft sign -a dilithium -s --hexseed=abc123... "Hello World"

# Quiet mode (signature only)
qrlft sign -a dilithium --quiet --keyfile=mykey.private.hexseed document.txt
```

### Verify Signatures

```bash
# From signature file
qrlft verify -a dilithium --sigfile=document.sig --pkfile=mykey.pub document.txt

# From command line
qrlft verify -a dilithium --signature=abc123... --publickey=def456... document.txt

# ML-DSA-87 with context
qrlft verify -a mldsa --context="myapp" --sigfile=document.sig --pkfile=mykey.pub document.txt
```

### Extract Public Key

```bash
# Write to file
qrlft publickey -a dilithium --hexseed=abc123... mykey.pub

# Print to console
qrlft publickey -a dilithium --print --hexseed=abc123...

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

Keys are stored using RFC 7468 textual encodings:

**Dilithium:**
```
-----BEGIN DILITHIUM PRIVATE KEY-----
...base64 encoded key...
-----END DILITHIUM PRIVATE KEY-----
```

Legacy pre-FIPS Dilithium has no finalized PKIX key format, so its labels and
raw payload remain qrlft-specific.

**ML-DSA-87 (RFC 9881):**
```
-----BEGIN PRIVATE KEY-----
...base64 encoded PKCS#8 OneAsymmetricKey containing the seed...
-----END PRIVATE KEY-----

-----BEGIN PUBLIC KEY-----
...base64 encoded SubjectPublicKeyInfo...
-----END PUBLIC KEY-----
```

The algorithm remains required. When a PEM key file is supplied, its custom
header or, for standard ML-DSA files, its algorithm identifier is detected and
checked against `--algorithm`; a mismatch is rejected. Older qrlft ML-DSA files
with algorithm-specific labels remain readable for migration.

## ML-DSA-87 Context

ML-DSA-87 (FIPS 204) requires a context parameter for domain separation:

- Context is a string of 0-255 bytes
- Must be the same for signing and verification
- Signatures created with one context won't verify with another

```bash
# Sign with context
qrlft sign -a mldsa --context="myapp-v1" --keyfile=key doc.txt > doc.sig

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

## Verifying a Release

Every release archive is signed in CI with ML-DSA-87 (FIPS 204). Each release
publishes a `qrlft_<tag>_signatures.txt` alongside the binaries, holding one
line per archive:

```
<hex signature> qrlft_v4.1.0_linux_amd64.zip
```

Release signatures use the context string **`qrlft-release-signatures`**. A
signature only verifies under that exact context, so it has to be passed on
every verification.

### Release public key

The signing key is checked in as [`theqrl-release-key.pub`](theqrl-release-key.pub):

```
-----BEGIN PUBLIC KEY-----
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
4YW4ZRZzImtYSjkOqjKu29uM+Yk0rQ==
-----END PUBLIC KEY-----
```

### Checking an archive

Download the archive and the signatures file from the release, then pull out the
line for your archive and verify it. `--sigfile` expects a file holding nothing
but the signature, so the signatures file cannot be passed to it directly:

```bash
FILE=qrlft_v4.1.0_linux_amd64.zip
SIG=$(grep " $FILE\$" qrlft_v4.1.0_signatures.txt | cut -d' ' -f1)

qrlft verify -a mldsa \
  --context="qrlft-release-signatures" \
  --signature="$SIG" \
  --pkfile=theqrl-release-key.pub \
  "$FILE"
```

`Signature is valid` with exit code 0 means the archive is byte-for-byte what CI
built and signed. A modified archive, the wrong key, or a mistyped context all
print `Signature is not valid` and exit 1 — treat any of these as a failed
download and do not run the binary.

## Security Considerations

- **Private key files** are created with `0600` permissions (owner read/write only)
- **Public key files** are created with `0644` permissions (world-readable)
- **Do not expose as a service**: This is a CLI tool designed for local use. Post-quantum cryptographic operations are computationally expensive. If you need to expose signing/verification as a service, implement proper rate limiting, authentication, and resource controls
- **Context for ML-DSA-87**: Always use a unique, application-specific context string to ensure domain separation between different uses of the same key

## Development checks

Run the complete local gate with `make check`. Coverage is ratcheted at 100%:
`make coverage` generates `coverage.out`, applies source-level exclusions with
the pinned `go-ignore-cov` version, and fails unless the processed profile is
exactly 100%. Every exclusion must use an approved reason from
`.coverage-reasons.yml` and include an adjacent `//rationale:` comment;
testable behavior must be covered by a test instead.

## License

MIT
