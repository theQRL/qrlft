# Release Process

This project uses [semantic-release](https://semantic-release.gitbook.io/) to automate versioning and releases based on commit messages.

## How It Works

1. Push commits to `main` branch
2. CI analyzes commit messages since the last release
3. Version is automatically bumped based on commit types
4. Changelog is generated
5. GitHub release is created with binaries

## Cryptographic dependencies

ML-DSA-87 comes from [go-qrllib](https://github.com/theQRL/go-qrllib). Dilithium
does not: go-qrllib removed it at v0.9.0, and qrlft still has to verify releases
signed before FIPS 204 was finalised, so that implementation is vendored at
[`internal/dilithium`](internal/dilithium) with the numeric helpers it needs in
[`internal/lattice`](internal/lattice). Both are copied unchanged from go-qrllib
v0.8.0 apart from their import paths. See
[internal/dilithium/PROVENANCE.md](internal/dilithium/PROVENANCE.md).

The split means go-qrllib can be followed forward without carrying a scheme it
has finished with, and without stranding signatures already published.

Bumping go-qrllib therefore affects ML-DSA-87 only. Two checks belong with any
such bump, because neither is caught by the unit tests:

1. Verify a signature published under the old version against the released
   public key. Signature output changing is the failure that looks like a forged
   download rather than a broken dependency.
2. Confirm `sign -a mldsa` still emits 4627-byte signatures. ML-DSA-87 and
   Dilithium5 differ only in signature length, 4627 against 4595, and share a
   public key size.

The vendored tree is frozen. Its upstream tests came with it and are the
evidence it still behaves like the code that produced signatures now in the
wild, so they are expected to keep passing untouched.

## Release Signing

After goreleaser builds `dist/*.zip`, CI signs every archive with ML-DSA-87
(FIPS 204) via the pinned `theQRL/actions-mldsa-sign` action and uploads the
result to the release as `qrlft_<tag>_signatures.txt`.

- Context string: `qrlft-release-signatures` — signatures do not verify without it
- Signing key: repository secret `MLDSA_HEXSEED` (the hexseed for
  `theqrl-release-key.pub`, which is committed at the repo root)

Consumer-facing verification steps live in
[README.md](README.md#verifying-a-release). Rotating the key means generating a
new keypair with the same context, replacing the `MLDSA_HEXSEED` secret, and
committing the new `theqrl-release-key.pub` — previously published signatures
still verify only under the old key, so keep it available.

## Commit Message Format

Commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types and Version Bumps

| Type | Description | Version Bump |
|------|-------------|--------------|
| `fix:` | Bug fixes | Patch (1.0.0 → 1.0.1) |
| `feat:` | New features | Minor (1.0.0 → 1.1.0) |
| `feat!:` or `BREAKING CHANGE:` | Breaking changes | Major (1.0.0 → 2.0.0) |
| `docs:` | Documentation only | No release |
| `style:` | Formatting, whitespace | No release |
| `refactor:` | Code restructuring | No release |
| `perf:` | Performance improvements | Patch |
| `test:` | Adding/updating tests | No release |
| `chore:` | Maintenance tasks | No release |
| `ci:` | CI/CD changes | No release |

### Examples

**Patch Release (1.0.0 → 1.0.1):**
```
fix: correct signature verification for empty files
```

**Minor Release (1.0.0 → 1.1.0):**
```
feat: add ML-DSA-87 signing algorithm support
```

**Major Release (1.0.0 → 2.0.0):**
```
feat!: change default algorithm from dilithium to mldsa

BREAKING CHANGE: The default signing algorithm has changed.
Existing scripts using implicit dilithium must add -a dilithium flag.
```

**With Scope:**
```
feat(sign): add --context flag for ML-DSA-87
fix(verify): handle trailing whitespace in signature files
```

**No Release (maintenance):**
```
docs: update README with ML-DSA examples
chore: update dependencies
test: add integration tests for new command
```

## Manual Commits (No Release)

To explicitly skip a release, add `[skip release]` or `[no release]` to commit message:

```
chore: update dev dependencies [skip release]
```

## Triggering a Release

Simply push conforming commits to `main`:

```bash
git add .
git commit -m "feat: add new hashing algorithm"
git push origin main
```

CI will handle the rest automatically.

## Pre-release Versions

Commits to `beta` or `alpha` branches create pre-releases:

- `beta` → `1.1.0-beta.1`
- `alpha` → `1.1.0-alpha.1`

## Checking What Will Release

To preview what semantic-release would do without actually releasing:

```bash
npx semantic-release --dry-run
```

## Tips

1. **One logical change per commit** - Makes changelog cleaner
2. **Use scopes** - Groups related changes: `feat(cli):`, `fix(crypto):`
3. **Be descriptive** - Commit messages become changelog entries
4. **Breaking changes** - Always document migration path in body
