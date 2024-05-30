package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/theQRL/qrlft/checksum"
	"github.com/theQRL/qrlft/sign"
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
				Name:  "sign",
				Usage: "signs a file with a dilithium signature [eg. qrlft sign --hexseed=f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb7184da84a092f842b2a06d72a24a5d28 doc.txt",
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
				},
				Action: func(ctx *cli.Context) error {
					if ctx.String("hexseed") == "" {
						return cli.Exit("No hexseed provided", 78)
					}
					hexseed := ctx.String("hexseed")
					files := ctx.Args().Slice()
					if len(files) == 0 {
						return cli.Exit("No file provided", 82)
					}
					for _, file := range files {
						file := file
						signature, err := sign.SignFile(file, hexseed)
						if err != nil {
							return cli.Exit("Error when signing "+file, 79)
						}
						output(file, signature, ctx.Bool("quiet"))
					}
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
				},
				Action: func(ctx *cli.Context) error {
					action := false
					files := ctx.Args().Slice()
					if len(files) == 0 {
						return cli.Exit("No file provided", 82)
					}
					for _, file := range files {
						file := file

						// sha3-512
						if ctx.Bool("sha3-512") {
							x, err := checksum.SHA3512sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// keccak-256
						if ctx.Bool("keccak-256") {
							x, err := checksum.Keccak256sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// keccak-512
						if ctx.Bool("keccak-512") {
							x, err := checksum.Keccak512sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// sha256
						if ctx.Bool("sha256") {
							x, err := checksum.SHA256sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// md5
						if ctx.Bool("md5") {
							x, err := checksum.MD5sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// crc32
						if ctx.Bool("crc32") {
							x, err := checksum.CRC32(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// sha1
						if ctx.Bool("sha1") {
							x, err := checksum.SHA1sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// blake2s
						if ctx.Bool("blake2s") {
							x, err := checksum.Blake2s256(file)
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
