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
			file := ctx.Args().Get(0)
			if file == "" && !ctx.Bool("salt") {
				return cli.Exit("No file provided", 82)
			}
			if file == "" && ctx.Bool("salt") {
				return cli.Exit("Please specify a salt size: [eg: qrlft --salt 16]", 81)
			}
			// sha256
			if ctx.Bool("sha256") {
				if !ctx.Bool("quiet") {
					fmt.Printf("SHA256 checksum of %s\n", file)
				}
				x, err := checksum.SHA256sum(file)
				// if file doesn't exist return an error
				if err != nil {
					return cli.Exit("File "+file+" not found", 83)
				}
				return cli.Exit(x, 0)
			}

			// md5
			if ctx.Bool("md5") {
				if !ctx.Bool("quiet") {
					fmt.Printf("MD5 checksum of %s\n", file)
				}
				x, err := checksum.MD5sum(file)
				// if file doesn't exist return an error
				if err != nil {
					return cli.Exit("File "+file+" not found", 83)
				}
				return cli.Exit(x, 0)
			}

			// crc32
			if ctx.Bool("crc32") {
				if !ctx.Bool("quiet") {
					fmt.Printf("CRC32 checksum of %s\n", file)
				}
				x, err := checksum.CRC32(file)
				// if file doesn't exist return an error
				if err != nil {
					return cli.Exit("File "+file+" not found", 83)
				}
				return cli.Exit(x, 0)
			}

			// sha1
			if ctx.Bool("sha1") {
				if !ctx.Bool("quiet") {
					fmt.Printf("SHA1 checksum of %s\n", file)
				}
				x, err := checksum.SHA1sum(file)
				// if file doesn't exist return an error
				if err != nil {
					return cli.Exit("File "+file+" not found", 83)
				}
				return cli.Exit(x, 0)
			}

			// blake2s
			if ctx.Bool("blake2s") {
				if !ctx.Bool("quiet") {
					fmt.Printf("BLAKE2s checksum of %s\n", file)
				}
				x, err := checksum.Blake2s256(file)
				// if file doesn't exist return an error
				if err != nil {
					return cli.Exit("File "+file+" not found", 83)
				}
				return cli.Exit(x, 0)
			}

			// just make some salt
			if ctx.Bool("salt") {
				saltSize, _ := strconv.Atoi(ctx.Args().Get(0))
				salt := generateRandomSalt(saltSize)
				if !ctx.Bool("quiet") {
					fmt.Printf("Generating %d bytes of salt as a hexstring\n", saltSize)
				}
				return cli.Exit(hex.EncodeToString(salt), 0)

			}

			// no action selected
			return cli.Exit("No action selected", 84)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
