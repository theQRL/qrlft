
package sign

import (
	"testing"
)

func TestSignString(t *testing.T) {
	hexseed := "a3c0d45de8b5053d44888d6cc9a8690db5c9296ade4f524f252de893477ff849c11a95e8a9477297634064f207500d14"
	signature, err := SignString("test", hexseed)
	if err != nil {
		t.Errorf("SignString() error = %v", err)
	}
	if len(signature) != 9190 {
		t.Errorf("SignString() = %v, want %v", len(signature), 9190)
	}
}
