package hash

import (
	"strings"
	"testing"
)

func TestKeccak256Reader(t *testing.T) {
	reader := strings.NewReader("test")
	hash, err := Keccak256Reader(reader)
	if err != nil {
		t.Errorf("Keccak256Reader() error = %v", err)
	}
	if hash != "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658" {
		t.Errorf("Keccak256Reader() = %v, want %v", hash, "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
	}
}

func TestKeccak512Reader(t *testing.T) {
	reader := strings.NewReader("test")
	hash, err := Keccak512Reader(reader)
	if err != nil {
		t.Errorf("Keccak512Reader() error = %v", err)
	}
	if hash != "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e" {
		t.Errorf("Keccak512Reader() = %v, want %v", hash, "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e")
	}
}

func TestSHA3512Reader(t *testing.T) {
	reader := strings.NewReader("test")
	hash, err := SHA3512Reader(reader)
	if err != nil {
		t.Errorf("SHA3512Reader() error = %v", err)
	}
	if hash != "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14" {
		t.Errorf("SHA3512Reader() = %v, want %v", hash, "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14")
	}
}

func TestSHA256sumReader(t *testing.T) {
	reader := strings.NewReader("test")
	hash, err := SHA256sumReader(reader)
	if err != nil {
		t.Errorf("SHA256sumReader() error = %v", err)
	}
	if hash != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Errorf("SHA256sumReader() = %v, want %v", hash, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	}
}

func TestBlake2s256Reader(t *testing.T) {
	reader := strings.NewReader("test")
	hash, err := Blake2s256Reader(reader)
	if err != nil {
		t.Errorf("Blake2s256Reader() error = %v", err)
	}
	if hash != "f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e" {
		t.Errorf("Blake2s256Reader() = %v, want %v", hash, "f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e")
	}
}
