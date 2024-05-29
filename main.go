package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/theqrl/qrlft/checksum"
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

//
// func hashWithSalt() {
//   data := []byte("Hello, World!")
// 	salt := generateRandomSalt(16)
// 	hash := sha256.Sum256(data)
//   hashWithSalt := sha256.Sum256(append(data, salt...))
//   fmt.Printf("SHA-256 hash: %x\n", hash)
// 	fmt.Printf("Salt: %x\n", salt)
// 	fmt.Printf("SHA-256 hash with salt: %x\n", hashWithSalt)
// }

func main() {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "sha3-512",
				Usage: "hash with SHA3-512",
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
				Name:  "salt",
				Usage: "create some random salt",
			},
			&cli.BoolFlag{
				Name:  "quiet",
				Usage: "just output the hash, no filename",
			},
		},
		Action: func(ctx *cli.Context) error {
			action := false
			files := ctx.Args().Slice()
			if len(files) == 0 && !ctx.Bool("salt") {
				return cli.Exit("No file provided", 82)
			}
			if len(files) == 0 && ctx.Bool("salt") {
				return cli.Exit("Please specify a salt size: [eg: qrlft --salt 16]", 81)
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

				// just make some salt
				if ctx.Bool("salt") {
					saltSize, _ := strconv.Atoi(ctx.Args().Get(0))
					salt := generateRandomSalt(saltSize)
					if !ctx.Bool("quiet") {
						fmt.Printf("Generating %d bytes of salt as a hexstring\n", saltSize)
					}
					fmt.Printf("%s\n", hex.EncodeToString(salt))
					action = true
				}
			}
			if action {
				return cli.Exit("", 0)
			}
			return cli.Exit("No action selected", 84)

		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
