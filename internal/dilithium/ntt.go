package dilithium

import "github.com/theQRL/qrlft/v4/internal/lattice"

func ntt(a *[N]int32) {
	lattice.NTT(a)
}

func invNTTToMont(a *[N]int32) {
	lattice.InvNTTToMont(a)
}
