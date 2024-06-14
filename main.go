package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/theQRL/go-qrllib/dilithium"
	"github.com/theQRL/qrlft/hash"
	"github.com/theQRL/qrlft/sign"
	"github.com/theQRL/qrlft/verify"
	"github.com/urfave/cli/v2"
)

func generateRandomSalt(saltSize int) []byte {
	var salt = make([]byte, saltSize)
	_, err := rand.Read(salt[:])
	if err != nil {
		panic(err)
	}
	return salt
}

func output(filename string, hash string, quiet bool) {
	if !quiet {
		fmt.Printf("%s %s\n", hash, filename)
		return
	}
	fmt.Printf("%s\n", hash)
}

func main() {
	app := &cli.App{
		Name:  "qrlft",
		Usage: "QRL File Tools - See docs at https://github.com/theQRL/qrlft",
		Commands: []*cli.Command{
			{
				Name:  "verify",
				Usage: "verify a dilithium signature matches the target file [eg. qrlft verify --signature=3b4e... doc.txt]",
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
				},
				Action: func(ctx *cli.Context) error {

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
					for _, file := range files {
						file := file

						filecheck, err := os.Open(file)
						if err != nil {
							return cli.Exit("Error when verifying "+file, 78)
						}
						defer filecheck.Close()

						fileinfo, err := filecheck.Stat()
						if err != nil {
							return cli.Exit("Error when verifying "+file, 77)
						}
						if fileinfo.IsDir() {
							// skip this iteration
							continue
						}
						signature := ctx.String("signature")

						if ctx.String("sigfile") != "" {
							sigfile, err := os.Open(ctx.String("sigfile"))
							if err != nil {
								return cli.Exit("Could not open signature file "+ctx.String("sigfile"), 71)
							}
							defer sigfile.Close()

							sigfileinfo, err := sigfile.Stat()
							if err != nil {
								return cli.Exit("Could not open signature file "+ctx.String("sigfile"), 70)
							}
							if sigfileinfo.IsDir() {
								return cli.Exit("Could not open signature file "+ctx.String("sigfile")+" - is it a folder?", 72)
							}
							// load contents of sigfile into string
							sigfilebuffer := make([]byte, sigfileinfo.Size())
							_, err = sigfile.Read(sigfilebuffer)
							if err != nil {
								return cli.Exit("Could not read signature file "+ctx.String("sigfile"), 69)
							}
							signature = string(sigfilebuffer)
							// trim string to be correct signature length
							signature = signature[:9190]
						}
						pk := ctx.String("publickey")
						if ctx.String("pkfile") != "" {
							pkfile, err := os.Open(ctx.String("pkfile"))
							if err != nil {
								return cli.Exit("Could not open public key file "+ctx.String("pkfile"), 71)
							}
							defer pkfile.Close()

							pkfileinfo, err := pkfile.Stat()
							if err != nil {
								return cli.Exit("Could not open public key file "+ctx.String("pkfile"), 70)
							}
							if pkfileinfo.IsDir() {
								return cli.Exit("Could not open public key file "+ctx.String("pkfile")+" - is it a folder?", 72)
							}
							// load contents of pkfile into string
							pkfilebuffer := make([]byte, pkfileinfo.Size())
							_, err = pkfile.Read(pkfilebuffer)
							if err != nil {
								return cli.Exit("Could not read public key file "+ctx.String("pkfile"), 69)
							}
							pk = string(pkfilebuffer)
							pk = pk[:5184]
						}

						verified, err := verify.VerifyFile(file, signature, pk)
						if err != nil {
							fmt.Printf("Error: %a", err)
							return cli.Exit("Error when verifying "+file, 79)
						}
						if verified {
							return cli.Exit("Signature is valid", 0)
						}
						if !verified {
							return cli.Exit("Signature is not valid", 1)
						}
					}
					return cli.Exit("", 0)
				},
			},
			{
				Name:  "sign",
				Usage: "signs a file with a dilithium signature [eg. qrlft sign --hexseed=f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb7184da84a092f842b2a06d72a24a5d28 doc.txt]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "hexseed",
						Aliases: []string{"hs"},
						Usage:   "Signs file using the private key `SEED`",
					},
					&cli.BoolFlag{
						Name:  "quiet",
						Usage: "just output the signature, no filename",
					},
					&cli.BoolFlag{
						Name:    "string",
						Aliases: []string{"s"},
						Usage:   "hash a string instead of a file [eg. qrlft hash --sha256 HashThisText]",
					},
				},
				Action: func(ctx *cli.Context) error {
					if ctx.String("hexseed") == "" {
						return cli.Exit("No hexseed provided", 78)
					}
					hexseed := ctx.String("hexseed")
					files := ctx.Args().Slice()

					if ctx.Bool("string") {
						if len(files) == 0 {
							return cli.Exit("No string provided", 74)
						}
						signature, err := sign.SignString(files[0], hexseed)
						if err != nil {
							return cli.Exit("Error when signing "+files[0], 75)
						}
						return cli.Exit(signature, 0)
					}

					if len(files) == 0 {
						return cli.Exit("No file provided", 82)
					}
					if len(files) == 1 {
						files, _ = filepath.Glob(files[0])
					}
					for _, file := range files {
						file := file

						filecheck, err := os.Open(file)
						if err != nil {
							return cli.Exit("Error when signing "+file+" - "+err.Error(), 78)
						}
						defer filecheck.Close()

						fileinfo, err := filecheck.Stat()
						if err != nil {
							return cli.Exit("Error when signing "+file, 77)
						}
						if fileinfo.IsDir() {
							// skip this iteration
							continue
						}
						signature, err := sign.SignFile(file, hexseed)
						if err != nil {
							fmt.Printf("Error: %a", err)
							return cli.Exit("Error when signing "+file, 79)
						}
						output(file, signature, ctx.Bool("quiet"))
					}
					return cli.Exit("", 0)
				},
			},
			{
				Name:  "publickey",
				Usage: "outputs the public key for a private hexseed to a file or to console [eg. qrlft publickey --hexseed=f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb7184da84a092f842b2a06d72a24a5d28 mykey.pub]",
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
						Usage:   "prints the public key to the console instead of writing to a file [eg. qrlft publickey --print --hexseed=f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb7184da84a092f842b2a06d72a24a5d28]",
					},
				},
				Action: func(ctx *cli.Context) error {
					if ctx.String("hexseed") == "" {
						return cli.Exit("No hexseed provided", 78)
					}
					hexseed := ctx.String("hexseed")
					files := ctx.Args().Slice()
					writeToConsole := false

					if ctx.Bool("print") {
						writeToConsole = true
					}
					if len(files) == 0 && !writeToConsole {
						return cli.Exit("Please specify an output file or use the --print flag to dump the public key to the console", 62)
					}
					d, err := dilithium.NewDilithiumFromHexSeed(hexseed)
					pkBin := d.GetPK()
					pk := hex.EncodeToString(pkBin[:])
					if err != nil {
						cli.Exit("failed to generate dilithium public key from the hexseed provided", 61)
					}
					if !writeToConsole {
						if err := os.WriteFile(files[0], []byte(pk), 0644); err != nil {
							return cli.Exit("failed to write public key to file", 62)
						}
						return cli.Exit("", 0)
					} else {
						fmt.Printf("%s\n", pk)
					}
					// }
					return cli.Exit("", 0)
				},
			},
			{
				Name:  "hash",
				Usage: "hashes a file with algorithm selected in options [eg. qrlft hash --sha256 doc.txt]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "sha3-512",
						Usage: "hash with SHA3-512",
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
						Name:  "sha256",
						Usage: "hash with SHA256",
					},
					&cli.BoolFlag{
						Name:  "sha1",
						Usage: "hash with SHA1",
					},
					&cli.BoolFlag{
						Name:  "md5",
						Usage: "hash with MD5",
					},
					&cli.BoolFlag{
						Name:  "crc32",
						Usage: "hash with CRC32",
					},
					&cli.BoolFlag{
						Name:  "blake2s",
						Usage: "hash with BLAKE2s",
					},
					&cli.BoolFlag{
						Name:  "quiet",
						Usage: "just output the hash, no filename",
					},
					&cli.BoolFlag{
						Name:    "string",
						Aliases: []string{"s"},
						Usage:   "hash a string instead of a file [eg. qrlft hash --sha256 HashThisText]",
					},
				},
				Action: func(ctx *cli.Context) error {
					action := false
					files := ctx.Args().Slice()

					if ctx.Bool("string") {
						if len(files) == 0 {
							return cli.Exit("No string provided", 73)
						}
						if ctx.Bool("sha256") {
							return cli.Exit(hash.SHA256string(files[0]), 0)
						}
						if ctx.Bool("sha1") {
							return cli.Exit(hash.SHA1string(files[0]), 0)
						}
						if ctx.Bool("md5") {
							return cli.Exit(hash.MD5string(files[0]), 0)
						}
						if ctx.Bool("crc32") {
							return cli.Exit(hash.CRC32string(files[0]), 0)
						}
						if ctx.Bool("sha3-512") {
							return cli.Exit(hash.SHA3512string(files[0]), 0)
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
						filecheck, err := os.Open(file)
						if err != nil {
							return cli.Exit("Error when hashing "+file+" - "+err.Error(), 78)
						}
						defer filecheck.Close()

						fileinfo, err := filecheck.Stat()
						if err != nil {
							return cli.Exit("Error when hashing "+file, 77)
						}
						if fileinfo.IsDir() {
							// skip this iteration
							continue
						}
						// sha3-512
						if ctx.Bool("sha3-512") {
							x, err := hash.SHA3512sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// keccak-256
						if ctx.Bool("keccak-256") {
							x, err := hash.Keccak256sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// keccak-512
						if ctx.Bool("keccak-512") {
							x, err := hash.Keccak512sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// sha256
						if ctx.Bool("sha256") {
							x, err := hash.SHA256sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// md5
						if ctx.Bool("md5") {
							x, err := hash.MD5sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// crc32
						if ctx.Bool("crc32") {
							x, err := hash.CRC32(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// sha1
						if ctx.Bool("sha1") {
							x, err := hash.SHA1sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// blake2s
						if ctx.Bool("blake2s") {
							x, err := hash.Blake2s256(file)
							// if file doesn't exist return an error
							if err != nil {
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
					salt := generateRandomSalt(saltSize)
					if !ctx.Bool("quiet") {
						fmt.Printf("Generating random %d bytes of salt as a hexstring\n", saltSize)
					}
					fmt.Printf("%s\n", hex.EncodeToString(salt))
					return cli.Exit("", 0)
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
