package dilithium

import "github.com/theQRL/qrlft/v4/internal/lattice"

func montgomeryReduce(a int64) int32 {
	return lattice.MontgomeryReduce(a)
}

func reduce32(a int32) int32 {
	return lattice.Reduce32(a)
}

func cAddQ(a int32) int32 {
	return lattice.CAddQ(a)
}
