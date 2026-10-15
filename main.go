package main

import (
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	qcrypto "github.com/theQRL/qrlft/v4/crypto"
	"github.com/theQRL/qrlft/v4/hash"
	"github.com/theQRL/qrlft/v4/sign"
	"github.com/theQRL/qrlft/v4/verify"
	"github.com/urfave/cli/v2"
)

func generateRandomSalt(saltSize int) ([]byte, error) {
	var salt = make([]byte, saltSize)
	_, err := rand.Read(salt[:])
	if err != nil {
		//coverage:ignore reason=statistically-unreachable
		//rationale: crypto/rand.Read fails only when the operating system entropy source is unavailable
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	return salt, nil
}

func output(filename string, hash string, quiet bool) {
	if !quiet {
		fmt.Printf("%s %s\n", hash, filename)
		return
	}
	fmt.Printf("%s\n", hash)
}

func hexStringToRFC7468(hexString string) (string, error) {
	decoded, err := hex.DecodeString(hexString)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex string: %w", err)
	}
	sEnc := b64.StdEncoding.EncodeToString([]byte(decoded))
	sArray := split(sEnc, 64)
	sEnc = ""
	for _, chunk := range sArray {
		sEnc = sEnc + "\n" + chunk
	}
	return sEnc, nil
}

func split(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]

	}
	return ss
}

// trimHexPrefix removes the 0x or 0X prefix from a hex string if present
func trimHexPrefix(s string) string {
	if len(s) >= 2 && strings.EqualFold(s[:2], "0x") {
		return s[2:]
	}
	return s
}

// readKeyFromFile reads a key file and detects if it's a hexseed or private key
// Returns the hexseed string, detected algorithm, and an error
func readKeyFromFile(filepath string) (string, string, error) {
	// #nosec G304 -- the CLI is explicitly designed to read a user-selected key file.
	file, err := os.Open(filepath)
	if err != nil {
		return "", "", fmt.Errorf("could not open key file %s: %w", filepath, err)
	}
	defer func() { _ = file.Close() }()

	fileinfo, err := file.Stat()
	if err != nil {
		//coverage:ignore reason=statistically-unreachable
		//rationale: the key descriptor was just opened; failure requires an external filesystem race
		return "", "", fmt.Errorf("could not stat key file %s: %w", filepath, err)
	}
	if fileinfo.IsDir() {
		return "", "", fmt.Errorf("key file %s is a directory", filepath)
	}

	filebuffer, err := io.ReadAll(file)
	if err != nil {
		//coverage:ignore reason=statistically-unreachable
		//rationale: reading a just-opened regular file fails only under external mutation
		return "", "", fmt.Errorf("could not read key file %s: %w", filepath, err)
	}

	content := strings.TrimSpace(string(filebuffer))

	// Detect algorithm from PEM headers
	detectedAlgo := qcrypto.DetectAlgorithmFromPEM(content)

	// RFC 9881 ML-DSA-87 private key (PKCS#8 / OneAsymmetricKey). Prefer
	// the seed when present because go-qrllib can reconstruct the keypair.
	if strings.HasPrefix(content, "-----BEGIN PRIVATE KEY-----") {
		seed, expandedKey, err := qcrypto.ParseMLDSAPrivateKeyPEM([]byte(content))
		if err != nil {
			return "", "", fmt.Errorf("could not decode ML-DSA-87 private key: %w", err)
		}
		if len(seed) != 0 {
			return hex.EncodeToString(seed), qcrypto.AlgorithmMLDSA, nil
		}
		return "PRIVATEKEY:" + hex.EncodeToString(expandedKey), qcrypto.AlgorithmMLDSA, nil
	}

	// Check if it's a hexseed file (RFC7468 format) - Dilithium
	if strings.HasPrefix(content, "-----BEGIN DILITHIUM PRIVATE HEXSEED-----") {
		content = strings.TrimPrefix(content, "-----BEGIN DILITHIUM PRIVATE HEXSEED-----")
		content = strings.TrimSuffix(content, "-----END DILITHIUM PRIVATE HEXSEED-----")
		content = strings.TrimSpace(content)
		content = trimHexPrefix(content)
		return content, qcrypto.AlgorithmDilithium, nil
	}

	// Check if it's a hexseed file (RFC7468 format) - ML-DSA-87
	if strings.HasPrefix(content, "-----BEGIN ML-DSA-87 PRIVATE HEXSEED-----") {
		content = strings.TrimPrefix(content, "-----BEGIN ML-DSA-87 PRIVATE HEXSEED-----")
		content = strings.TrimSuffix(content, "-----END ML-DSA-87 PRIVATE HEXSEED-----")
		content = strings.TrimSpace(content)
		content = trimHexPrefix(content)
		return content, qcrypto.AlgorithmMLDSA, nil
	}

	// Check if it's a private key file (RFC7468 format) - Dilithium
	if strings.HasPrefix(content, "-----BEGIN DILITHIUM PRIVATE KEY-----") {
		content = strings.TrimPrefix(content, "-----BEGIN DILITHIUM PRIVATE KEY-----")
		content = strings.TrimSuffix(content, "-----END DILITHIUM PRIVATE KEY-----")
		content = strings.TrimSpace(content)
		content = strings.ReplaceAll(content, "\n", "")

		skBytes, err := b64.StdEncoding.DecodeString(content)
		if err != nil {
			return "", "", fmt.Errorf("could not decode base64 private key: %w", err)
		}

		privateKeyHex := hex.EncodeToString(skBytes)
		return "PRIVATEKEY:" + privateKeyHex, qcrypto.AlgorithmDilithium, nil
	}

	// Check if it's a private key file (RFC7468 format) - ML-DSA-87
	if strings.HasPrefix(content, "-----BEGIN ML-DSA-87 PRIVATE KEY-----") {
		content = strings.TrimPrefix(content, "-----BEGIN ML-DSA-87 PRIVATE KEY-----")
		content = strings.TrimSuffix(content, "-----END ML-DSA-87 PRIVATE KEY-----")
		content = strings.TrimSpace(content)
		content = strings.ReplaceAll(content, "\n", "")

		skBytes, err := b64.StdEncoding.DecodeString(content)
		if err != nil {
			return "", "", fmt.Errorf("could not decode base64 private key: %w", err)
		}

		privateKeyHex := hex.EncodeToString(skBytes)
		return "PRIVATEKEY:" + privateKeyHex, qcrypto.AlgorithmMLDSA, nil
	}

	// Assume it's a plain hexseed string (algorithm unknown)
	content = strings.TrimSpace(content)
	content = trimHexPrefix(content)
	_, err = hex.DecodeString(content)
	if err != nil {
		return "", "", fmt.Errorf("file does not contain a valid hexseed or private key format")
	}
	return content, detectedAlgo, nil
}

// readPublicKeyFromFile reads a public key file and returns the hex public key and detected algorithm
func readPublicKeyFromFile(filepath string) (string, string, error) {
	// #nosec G304 -- the CLI is explicitly designed to read a user-selected public key file.
	file, err := os.Open(filepath)
	if err != nil {
		return "", "", fmt.Errorf("could not open public key file %s: %w", filepath, err)
	}
	defer func() { _ = file.Close() }()

	fileinfo, err := file.Stat()
	if err != nil {
		//coverage:ignore reason=statistically-unreachable
		//rationale: the public-key descriptor was just opened; failure requires an external filesystem race
		return "", "", fmt.Errorf("could not stat public key file %s: %w", filepath, err)
	}
	if fileinfo.IsDir() {
		return "", "", fmt.Errorf("public key file %s is a directory", filepath)
	}

	pkfilebuffer, err := io.ReadAll(file)
	if err != nil {
		//coverage:ignore reason=statistically-unreachable
		//rationale: reading a just-opened regular file fails only under external mutation
		return "", "", fmt.Errorf("could not read public key file %s: %w", filepath, err)
	}

	pk := strings.TrimSpace(string(pkfilebuffer))

	// RFC 9881 ML-DSA-87 SubjectPublicKeyInfo.
	if strings.HasPrefix(pk, "-----BEGIN PUBLIC KEY-----") {
		pkBytes, err := qcrypto.ParseMLDSAPublicKeyPEM([]byte(pk))
		if err != nil {
			return "", "", fmt.Errorf("could not decode ML-DSA-87 public key: %w", err)
		}
		return hex.EncodeToString(pkBytes), qcrypto.AlgorithmMLDSA, nil
	}

	// Check for Dilithium PEM format
	if strings.HasPrefix(pk, "-----BEGIN DILITHIUM PUBLIC KEY-----") {
		pk = strings.TrimPrefix(pk, "-----BEGIN DILITHIUM PUBLIC KEY-----")
		pk = strings.TrimSuffix(pk, "-----END DILITHIUM PUBLIC KEY-----")
		pk = strings.TrimSpace(pk)
		pk = strings.ReplaceAll(pk, "\n", "")
		pkBytes, err := b64.StdEncoding.DecodeString(pk)
		if err != nil {
			return "", "", fmt.Errorf("could not decode base64 public key: %w", err)
		}
		return hex.EncodeToString(pkBytes), qcrypto.AlgorithmDilithium, nil
	}

	// Check for ML-DSA-87 PEM format
	if strings.HasPrefix(pk, "-----BEGIN ML-DSA-87 PUBLIC KEY-----") {
		pk = strings.TrimPrefix(pk, "-----BEGIN ML-DSA-87 PUBLIC KEY-----")
		pk = strings.TrimSuffix(pk, "-----END ML-DSA-87 PUBLIC KEY-----")
		pk = strings.TrimSpace(pk)
		pk = strings.ReplaceAll(pk, "\n", "")
		pkBytes, err := b64.StdEncoding.DecodeString(pk)
		if err != nil {
			return "", "", fmt.Errorf("could not decode base64 public key: %w", err)
		}
		return hex.EncodeToString(pkBytes), qcrypto.AlgorithmMLDSA, nil
	}

	// Assume plain hex string - truncate to expected size (Dilithium public key is 2592 bytes = 5184 hex chars)
	if len(pk) >= 5184 {
		return pk[:5184], "", nil
	}
	return pk, "", nil
}

// Algorithm and context flags used across commands
var algorithmFlag = &cli.StringFlag{
	Name:     "algorithm",
	Aliases:  []string{"a"},
	Usage:    "Signing algorithm: 'dilithium' or 'mldsa' (required)",
	Required: true,
}

var contextFlag = &cli.StringFlag{
	Name:    "context",
	Aliases: []string{"ctx"},
	Usage:   "Context string for ML-DSA-87 (required when using mldsa algorithm)",
}

func newApp() *cli.App {
	return &cli.App{
		Name:  "qrlft",
		Usage: "QRL File Tools - See docs at https://github.com/theQRL/qrlft",
		Commands: []*cli.Command{
			{
				Name:  "verify",
				Usage: "verify a signature matches the target file [eg. qrlft verify --signature=3b4e... doc.txt]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "sigfile",
						Aliases: []string{"sf"},
						Usage:   "Signature is a file [eg. qrlft verify --sigfile=signature.sig doc.txt]",
					},
					&cli.StringFlag{
						Name:    "signature",
						Aliases: []string{"s"},
						Usage:   "Signature is included on the command line [eg. qrlft verify --signature=3b4e... doc.txt]",
					},
					&cli.StringFlag{
						Name:    "publickey",
						Aliases: []string{"pk"},
						Usage:   "Specify the public key of the signer on command line [eg. qrlft verify --publickey=3b4e... doc.txt]",
					},
					&cli.StringFlag{
						Name:    "pkfile",
						Aliases: []string{"pkf"},
						Usage:   "Specify the public key of the signer in a file [eg. qrlft verify --pkfile=publickey.pub doc.txt]",
					},
					algorithmFlag,
					contextFlag,
				},
				Action: func(ctx *cli.Context) error {
					if err := qcrypto.ValidateAlgorithm(ctx.String("algorithm")); err != nil {
						return cli.Exit(err.Error(), 78)
					}
					if ctx.String("signature") == "" && ctx.String("sigfile") == "" {
						return cli.Exit("No signature provided", 78)
					}
					if ctx.String("publickey") == "" && ctx.String("pkfile") == "" {
						return cli.Exit("No public key provided", 78)
					}
					files := ctx.Args().Slice()
					if len(files) == 0 {
						return cli.Exit("No file provided", 82)
					}

					algorithm := ctx.String("algorithm")
					contextStr := ctx.String("context")
					var context []byte
					if algorithm == qcrypto.AlgorithmMLDSA {
						if contextStr == "" {
							return cli.Exit("Context is required for ML-DSA-87. Use --context flag.", 78)
						}
						context = []byte(contextStr)
					} else if contextStr != "" {
						context = []byte(contextStr) // Allow context for dilithium too (ignored)
					}

					checked, failed := 0, 0
					for _, file := range files {
						file := file

						// #nosec G304 -- the CLI is explicitly designed to verify a user-selected file.
						filecheck, err := os.Open(file)
						if err != nil {
							return cli.Exit("Error when verifying "+file, 78)
						}
						defer func() { _ = filecheck.Close() }()

						fileinfo, err := filecheck.Stat()
						if err != nil {
							//coverage:ignore reason=statistically-unreachable
							//rationale: the verification descriptor was just opened; failure requires a filesystem race
							return cli.Exit("Error when verifying "+file, 77)
						}
						if fileinfo.IsDir() {
							continue
						}
						signature := ctx.String("signature")

						if ctx.String("sigfile") != "" {
							sigfile, err := os.Open(ctx.String("sigfile"))
							if err != nil {
								return cli.Exit("Could not open signature file "+ctx.String("sigfile"), 71)
							}
							defer func() { _ = sigfile.Close() }()

							sigfileinfo, err := sigfile.Stat()
							if err != nil {
								//coverage:ignore reason=statistically-unreachable
								//rationale: the signature descriptor was just opened; failure requires a filesystem race
								return cli.Exit("Could not open signature file "+ctx.String("sigfile"), 70)
							}
							if sigfileinfo.IsDir() {
								return cli.Exit("Could not open signature file "+ctx.String("sigfile")+" - is it a folder?", 72)
							}
							sigfilebuffer, err := io.ReadAll(sigfile)
							if err != nil {
								//coverage:ignore reason=statistically-unreachable
								//rationale: reading a just-opened regular signature file fails only under external mutation
								return cli.Exit("Could not read signature file "+ctx.String("sigfile"), 69)
							}
							signature = strings.TrimSpace(string(sigfilebuffer))
						}

						pk := ctx.String("publickey")
						detectedAlgo := ""
						if ctx.String("pkfile") != "" {
							var err error
							pk, detectedAlgo, err = readPublicKeyFromFile(ctx.String("pkfile"))
							if err != nil {
								return cli.Exit(err.Error(), 71)
							}
							// Verify algorithm matches public key file format if detected
							if detectedAlgo != "" && detectedAlgo != algorithm {
								return cli.Exit(fmt.Sprintf("Algorithm mismatch: specified '%s' but public key file is '%s'", algorithm, detectedAlgo), 78)
							}
						}

						var verified bool
						if algorithm == qcrypto.AlgorithmMLDSA {
							verified, err = verify.VerifyFileWithAlgorithm(file, signature, pk, algorithm, context)
						} else {
							verified, err = verify.VerifyFile(file, signature, pk)
						}

						if err != nil {
							fmt.Printf("Error: %v\n", err)
							return cli.Exit("Error when verifying "+file, 79)
						}
						checked++
						if !verified {
							failed++
						}
						if len(files) > 1 {
							result := "OK"
							if !verified {
								result = "FAILED"
							}
							fmt.Printf("%s: %s\n", file, result)
						}
					}
					if checked == 0 {
						return cli.Exit("No file to verify", 82)
					}
					if failed > 0 {
						return cli.Exit("Signature is not valid", 1)
					}
					return cli.Exit("Signature is valid", 0)
				},
			},
			{
				Name:  "sign",
				Usage: "signs a file with a signature [eg. qrlft sign --hexseed=f29f58... doc.txt]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "hexseed",
						Aliases: []string{"hs"},
						Usage:   "Signs file using the private key `SEED`",
					},
					&cli.StringFlag{
						Name:    "keyfile",
						Aliases: []string{"kf"},
						Usage:   "Signs file using a private key or hexseed from a file. The function will automatically detect if it's a hexseed or private key.",
					},
					&cli.BoolFlag{
						Name:  "quiet",
						Usage: "just output the signature, no filename",
					},
					&cli.BoolFlag{
						Name:    "string",
						Aliases: []string{"s"},
						Usage:   "sign a string instead of a file [eg. qrlft sign --hexseed=... -s 'Hello World']",
					},
					algorithmFlag,
					contextFlag,
				},
				Action: func(ctx *cli.Context) error {
					if err := qcrypto.ValidateAlgorithm(ctx.String("algorithm")); err != nil {
						return cli.Exit(err.Error(), 78)
					}
					var hexseed string
					var err error
					var detectedAlgo string

					if ctx.String("hexseed") != "" && ctx.String("keyfile") != "" {
						return cli.Exit("Cannot use both --hexseed and --keyfile flags. Please use only one.", 78)
					}

					algorithm := ctx.String("algorithm")

					if ctx.String("hexseed") != "" {
						hexseed = ctx.String("hexseed")
						if len(hexseed) >= 2 && strings.EqualFold(hexseed[:2], "0x") {
							hexseed = hexseed[2:]
						}
					} else if ctx.String("keyfile") != "" {
						hexseed, detectedAlgo, err = readKeyFromFile(ctx.String("keyfile"))
						if err != nil {
							return cli.Exit("Error reading key file: "+err.Error(), 78)
						}
						// Verify algorithm matches key file format if detected
						if detectedAlgo != "" && detectedAlgo != algorithm {
							return cli.Exit(fmt.Sprintf("Algorithm mismatch: specified '%s' but key file is '%s'", algorithm, detectedAlgo), 78)
						}
					} else {
						return cli.Exit("No hexseed or keyfile provided. Please use --hexseed or --keyfile", 78)
					}

					contextStr := ctx.String("context")
					var context []byte
					if algorithm == qcrypto.AlgorithmMLDSA {
						if contextStr == "" {
							return cli.Exit("Context is required for ML-DSA-87. Use --context flag.", 78)
						}
						context = []byte(contextStr)
					} else if contextStr != "" {
						context = []byte(contextStr)
					}

					files := ctx.Args().Slice()

					// Check if we have a private key (prefixed with "PRIVATEKEY:") or a hexseed
					isPrivateKey := strings.HasPrefix(hexseed, "PRIVATEKEY:")
					var privateKeyHex string
					if isPrivateKey {
						privateKeyHex = strings.TrimPrefix(hexseed, "PRIVATEKEY:")
					}

					if ctx.Bool("string") {
						if len(files) == 0 {
							return cli.Exit("No string provided", 74)
						}
						var signature string
						if isPrivateKey {
							signature, err = sign.SignStringWithPrivateKeyAndAlgorithm(files[0], privateKeyHex, algorithm, context)
						} else if algorithm == qcrypto.AlgorithmMLDSA {
							signature, err = sign.SignStringWithAlgorithm(files[0], hexseed, algorithm, context)
						} else {
							signature, err = sign.SignString(files[0], hexseed)
						}
						if err != nil {
							return cli.Exit("Error when signing "+files[0]+": "+err.Error(), 75)
						}
						return cli.Exit(signature, 0)
					}

					if len(files) == 0 {
						return cli.Exit("No file provided", 82)
					}
					if len(files) == 1 {
						pattern := files[0]
						files, _ = filepath.Glob(pattern)
						if len(files) == 0 {
							return cli.Exit("No file matched "+pattern, 82)
						}
					}
					signed := 0
					for _, file := range files {
						file := file

						// #nosec G304 -- the CLI is explicitly designed to sign a user-selected file.
						filecheck, err := os.Open(file)
						if err != nil {
							return cli.Exit("Error when signing "+file+" - "+err.Error(), 78)
						}
						defer func() { _ = filecheck.Close() }()

						fileinfo, err := filecheck.Stat()
						if err != nil {
							//coverage:ignore reason=statistically-unreachable
							//rationale: the signing descriptor was just opened; failure requires a filesystem race
							return cli.Exit("Error when signing "+file, 77)
						}
						if fileinfo.IsDir() {
							continue
						}
						var signature string
						if isPrivateKey {
							signature, err = sign.SignFileWithPrivateKeyAndAlgorithm(file, privateKeyHex, algorithm, context)
						} else if algorithm == qcrypto.AlgorithmMLDSA {
							signature, err = sign.SignFileWithAlgorithm(file, hexseed, algorithm, context)
						} else {
							signature, err = sign.SignFile(file, hexseed)
						}
						if err != nil {
							fmt.Printf("Error: %v\n", err)
							return cli.Exit("Error when signing "+file+": "+err.Error(), 79)
						}
						output(file, signature, ctx.Bool("quiet"))
						signed++
					}
					if signed == 0 {
						return cli.Exit("No file to sign", 82)
					}
					return cli.Exit("", 0)
				},
			},
			{
				Name:  "publickey",
				Usage: "outputs the public key for a private hexseed to a file or to console [eg. qrlft publickey --hexseed=f29f58... mykey.pub]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "hexseed",
						Aliases: []string{"hs"},
						Usage:   "[Required] private key `SEED`",
					},
					&cli.BoolFlag{
						Name:  "quiet",
						Usage: "just output the signature, no filename",
					},
					&cli.BoolFlag{
						Name:    "print",
						Aliases: []string{"p"},
						Usage:   "prints the public key to the console instead of writing to a file",
					},
					algorithmFlag,
					contextFlag,
				},
				Action: func(ctx *cli.Context) error {
					if err := qcrypto.ValidateAlgorithm(ctx.String("algorithm")); err != nil {
						return cli.Exit(err.Error(), 78)
					}
					if ctx.String("hexseed") == "" {
						return cli.Exit("No hexseed provided", 78)
					}
					hexseed := ctx.String("hexseed")
					if len(hexseed) >= 2 && strings.EqualFold(hexseed[:2], "0x") {
						hexseed = hexseed[2:]
					}

					algorithm := ctx.String("algorithm")
					contextStr := ctx.String("context")
					var context []byte
					if algorithm == qcrypto.AlgorithmMLDSA {
						if contextStr == "" {
							return cli.Exit("Context is required for ML-DSA-87. Use --context flag.", 78)
						}
						context = []byte(contextStr)
					}

					files := ctx.Args().Slice()
					writeToConsole := ctx.Bool("print")
					if len(files) == 0 && !writeToConsole {
						return cli.Exit("Please specify an output file or use the --print flag to dump the public key to the console", 62)
					}

					signer, err := qcrypto.NewSigner(algorithm, hexseed, context)
					if err != nil {
						return cli.Exit("failed to generate public key from the hexseed provided: "+err.Error(), 61)
					}

					pkBin := signer.GetPK()
					pk := hex.EncodeToString(pkBin)

					if !writeToConsole {
						var publicKeyFile []byte
						if algorithm == qcrypto.AlgorithmMLDSA {
							publicKeyFile, err = qcrypto.MarshalMLDSAPublicKeyPEM(pkBin)
						} else {
							_, pemPK, _ := qcrypto.GetPEMHeaders(algorithm)
							pkPEM, encodeErr := hexStringToRFC7468(pk)
							if encodeErr != nil {
								//coverage:ignore reason=defensive-unreachable
								//rationale: pk comes from hex.EncodeToString and cannot fail hexadecimal decoding
								return cli.Exit("failed to encode public key: "+encodeErr.Error(), 63)
							}
							publicKeyFile = []byte("-----BEGIN " + pemPK + "-----" + pkPEM + "\n-----END " + pemPK + "-----\n")
						}
						if err != nil {
							//coverage:ignore reason=defensive-unreachable
							//rationale: the signer always returns a correctly sized ML-DSA-87 public key
							return cli.Exit("failed to encode public key: "+err.Error(), 63)
						}
						// #nosec G306 -- public keys are intentionally world-readable.
						if err := os.WriteFile(files[0], publicKeyFile, 0644); err != nil {
							return cli.Exit("failed to write public key to file", 62)
						}
						return cli.Exit("", 0)
					} else {
						fmt.Printf("%s\n", pk)
					}
					return cli.Exit("", 0)
				},
			},
			{
				Name:  "hash",
				Usage: "hashes a file with a post-quantum secure algorithm [eg. qrlft hash --sha3-512 doc.txt]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "sha3-512",
						Usage: "hash with SHA3-512 (recommended)",
					},
					&cli.BoolFlag{
						Name:  "sha256",
						Usage: "hash with SHA-256",
					},
					&cli.BoolFlag{
						Name:  "keccak-256",
						Usage: "hash with Keccak-256",
					},
					&cli.BoolFlag{
						Name:  "keccak-512",
						Usage: "hash with Keccak-512",
					},
					&cli.BoolFlag{
						Name:  "blake2s",
						Usage: "hash with BLAKE2s-256",
					},
					&cli.BoolFlag{
						Name:  "quiet",
						Usage: "just output the hash, no filename",
					},
					&cli.BoolFlag{
						Name:    "string",
						Aliases: []string{"s"},
						Usage:   "hash a string instead of a file [eg. qrlft hash --sha3-512 -s HashThisText]",
					},
				},
				Action: func(ctx *cli.Context) error {
					action := false
					files := ctx.Args().Slice()

					if ctx.Bool("string") {
						if len(files) == 0 {
							return cli.Exit("No string provided", 73)
						}
						if ctx.Bool("sha3-512") {
							return cli.Exit(hash.SHA3512string(files[0]), 0)
						}
						if ctx.Bool("sha256") {
							return cli.Exit(hash.SHA256string(files[0]), 0)
						}
						if ctx.Bool("keccak-256") {
							return cli.Exit(hash.Keccak256string(files[0]), 0)
						}
						if ctx.Bool("keccak-512") {
							return cli.Exit(hash.Keccak512string(files[0]), 0)
						}
						if ctx.Bool("blake2s") {
							return cli.Exit(hash.Blake2s256string(files[0]), 0)
						}
					}

					if len(files) == 0 {
						return cli.Exit("No file provided", 82)
					}
					if len(files) == 1 && !ctx.Bool("string") {
						files, _ = filepath.Glob(files[0])
					}
					for _, file := range files {
						file := file
						// #nosec G304 -- the CLI is explicitly designed to hash a user-selected file.
						filecheck, err := os.Open(file)
						if err != nil {
							return cli.Exit("Error when hashing "+file+" - "+err.Error(), 78)
						}
						defer func() { _ = filecheck.Close() }()

						fileinfo, err := filecheck.Stat()
						if err != nil {
							//coverage:ignore reason=statistically-unreachable
							//rationale: the hash descriptor was just opened; failure requires a filesystem race
							return cli.Exit("Error when hashing "+file, 77)
						}
						if fileinfo.IsDir() {
							continue
						}
						// sha3-512
						if ctx.Bool("sha3-512") {
							x, err := hash.SHA3512sum(file)
							if err != nil {
								//coverage:ignore reason=statistically-unreachable
								//rationale: the regular file was just opened and statted; failure requires a filesystem race
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// sha256
						if ctx.Bool("sha256") {
							x, err := hash.SHA256sum(file)
							if err != nil {
								//coverage:ignore reason=statistically-unreachable
								//rationale: the regular file was just opened and statted; failure requires a filesystem race
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// keccak-256
						if ctx.Bool("keccak-256") {
							x, err := hash.Keccak256sum(file)
							if err != nil {
								//coverage:ignore reason=statistically-unreachable
								//rationale: the regular file was just opened and statted; failure requires a filesystem race
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// keccak-512
						if ctx.Bool("keccak-512") {
							x, err := hash.Keccak512sum(file)
							if err != nil {
								//coverage:ignore reason=statistically-unreachable
								//rationale: the regular file was just opened and statted; failure requires a filesystem race
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// blake2s
						if ctx.Bool("blake2s") {
							x, err := hash.Blake2s256(file)
							if err != nil {
								//coverage:ignore reason=statistically-unreachable
								//rationale: the regular file was just opened and statted; failure requires a filesystem race
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}
					}

					if action {
						return cli.Exit("", 0)
					}
					return cli.Exit("No action selected", 84)
				},
			},
			{
				Name:  "salt",
				Usage: "generates user-specified bytes random salt [eg. qrlft salt 16]",
				Action: func(ctx *cli.Context) error {
					saltSize, _ := strconv.Atoi(ctx.Args().Get(0))
					if saltSize == 0 {
						return cli.Exit("Please specify a salt size: [eg: qrlft salt 16]", 81)
					}
					salt, err := generateRandomSalt(saltSize)
					if err != nil {
						//coverage:ignore reason=statistically-unreachable
						//rationale: generateRandomSalt fails only when the operating system entropy source is unavailable
						return cli.Exit("Failed to generate salt: "+err.Error(), 80)
					}
					if !ctx.Bool("quiet") {
						fmt.Printf("Generating random %d bytes of salt as a hexstring\n", saltSize)
					}
					fmt.Printf("%s\n", hex.EncodeToString(salt))
					return cli.Exit("", 0)
				},
			},
			{
				Name:    "new",
				Aliases: []string{"new-dilithium", "new-mldsa"},
				Usage:   "generates a new keypair [eg. qrlft new -a dilithium mykey | qrlft new -a mldsa --context=myapp mykey]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "print",
						Aliases: []string{"p"},
						Usage:   "prints the public/private keys and hexseed to the console instead of writing to a file",
					},
					algorithmFlag,
					contextFlag,
				},
				Action: func(ctx *cli.Context) error {
					if err := qcrypto.ValidateAlgorithm(ctx.String("algorithm")); err != nil {
						return cli.Exit(err.Error(), 78)
					}
					algorithm := ctx.String("algorithm")
					contextStr := ctx.String("context")
					var context []byte

					if algorithm == qcrypto.AlgorithmMLDSA {
						if contextStr == "" {
							return cli.Exit("Context is required for ML-DSA-87. Use --context flag.", 78)
						}
						context = []byte(contextStr)
					}

					signer, err := qcrypto.NewKeypair(algorithm, context)
					if err != nil {
						//coverage:ignore reason=statistically-unreachable
						//rationale: algorithm/context are validated; key generation fails only with OS entropy failure
						return cli.Exit("Failed to generate keypair: "+err.Error(), 61)
					}

					sk := signer.GetSK()
					pk := signer.GetPK()
					hs := signer.GetHexSeed()

					files := ctx.Args().Slice()
					writeToConsole := ctx.Bool("print")

					if len(files) == 0 && !writeToConsole {
						return cli.Exit("Please specify an output file or use the --print flag to dump the keys to the console", 62)
					}

					if writeToConsole {
						fmt.Printf("Private Key:\n%s\n\n", hex.EncodeToString(sk))
						fmt.Printf("Public Key: \n%s\n\n", hex.EncodeToString(pk))
						fmt.Printf("Hexseed: \n%s\n", hs)
					} else {
						fmt.Printf("Write to file: %s\n", files[0])
						if algorithm == qcrypto.AlgorithmMLDSA {
							seed, decodeErr := hex.DecodeString(trimHexPrefix(hs))
							if decodeErr != nil {
								//coverage:ignore reason=defensive-unreachable
								//rationale: GetHexSeed returns a hexadecimal encoding generated by go-qrllib
								return cli.Exit("failed to decode ML-DSA-87 seed: "+decodeErr.Error(), 63)
							}
							privateKeyFile, encodeErr := qcrypto.MarshalMLDSAPrivateKeyPEM(seed)
							if encodeErr != nil {
								//coverage:ignore reason=defensive-unreachable
								//rationale: go-qrllib always returns a correctly sized ML-DSA-87 seed
								return cli.Exit("failed to encode private key: "+encodeErr.Error(), 63)
							}
							publicKeyFile, encodeErr := qcrypto.MarshalMLDSAPublicKeyPEM(pk)
							if encodeErr != nil {
								//coverage:ignore reason=defensive-unreachable
								//rationale: the signer always returns a correctly sized ML-DSA-87 public key
								return cli.Exit("failed to encode public key: "+encodeErr.Error(), 63)
							}
							if err := os.WriteFile(files[0], privateKeyFile, 0600); err != nil {
								return cli.Exit("failed to write private key to file", 62)
							}
							// #nosec G306 -- public keys are intentionally world-readable.
							if err := os.WriteFile(files[0]+".pub", publicKeyFile, 0644); err != nil {
								return cli.Exit("failed to write public key to file", 62)
							}
							// Retain the established filename for consumers. RFC 9881 recommends
							// this same seed-only PKCS#8 representation for storage.
							if err := os.WriteFile(files[0]+".private.hexseed", privateKeyFile, 0600); err != nil {
								return cli.Exit("failed to write private hexseed to file", 62)
							}
							return cli.Exit("", 0)
						}

						pemSK, pemPK, pemHS := qcrypto.GetPEMHeaders(algorithm)
						skPEM, err := hexStringToRFC7468(hex.EncodeToString(sk))
						if err != nil {
							//coverage:ignore reason=defensive-unreachable
							//rationale: sk comes from hex.EncodeToString and cannot fail hexadecimal decoding
							return cli.Exit("failed to encode private key: "+err.Error(), 63)
						}
						pkPEM, err := hexStringToRFC7468(hex.EncodeToString(pk))
						if err != nil {
							//coverage:ignore reason=defensive-unreachable
							//rationale: pk comes from hex.EncodeToString and cannot fail hexadecimal decoding
							return cli.Exit("failed to encode public key: "+err.Error(), 63)
						}
						// Private key and hexseed files use 0600 (owner read/write only) for security
						if err := os.WriteFile(files[0], []byte("-----BEGIN "+pemSK+"-----"+skPEM+"\n-----END "+pemSK+"-----\n"), 0600); err != nil {
							return cli.Exit("failed to write private key to file", 62)
						}
						// #nosec G306 -- public keys are intentionally world-readable.
						if err := os.WriteFile(files[0]+".pub", []byte("-----BEGIN "+pemPK+"-----"+pkPEM+"\n-----END "+pemPK+"-----\n"), 0644); err != nil {
							return cli.Exit("failed to write public key to file", 62)
						}
						if err := os.WriteFile(files[0]+".private.hexseed", []byte("-----BEGIN "+pemHS+"-----\n"+hs+"\n-----END "+pemHS+"-----\n"), 0600); err != nil {
							return cli.Exit("failed to write private hexseed to file", 62)
						}
					}
					return cli.Exit("", 0)
				},
			},
		},
	}
}

func main() {
	//coverage:ignore reason=defensive-unreachable
	//rationale: process-exit wiring is exercised through newApp; calling main in a test would terminate the test process via log.Fatal
	if err := newApp().Run(os.Args); err != nil {
		//coverage:ignore reason=defensive-unreachable
		//rationale: cli failures are asserted as returned ExitCoder values through newApp, before the process-only log.Fatal boundary
		log.Fatal(err)
	}
}
