package sign

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestReadFileReturnsEveryByteOfALargeFile checks that a file larger than a
// single read call can return comes back whole.
func TestReadFileReturnsEveryByteOfALargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("reads just over 1 GiB into memory")
	}
	const tailLen = 40
	const size = int64(1<<30) + tailLen
	path := filepath.Join(t.TempDir(), "large.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	tail := bytes.Repeat([]byte("A"), tailLen)
	if _, err := f.WriteAt(tail, size-tailLen); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) != size {
		t.Fatalf("readFile returned %d bytes, want %d", len(data), size)
	}
	if !bytes.Equal(data[size-tailLen:], tail) {
		t.Fatalf("last %d bytes = %q, want %q", tailLen, data[size-tailLen:], tail)
	}
}
