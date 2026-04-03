package ecdh

type curve25519 struct{}

func (curve25519) multiply(scalar, point *[32]byte) [32]byte { return x25519(scalar, point) }

var _ scalarMultiplier = curve25519{}

func clampScalar(k *[32]byte) {
	k[0] &= 248  // clear bits 0,1,2 — cofactor 8
	k[31] &= 127 // clear bit 255
	k[31] |= 64  // set bit 254
}

func cswap(x, y *fieldElement, b uint64) {
	mask := uint64(0) - b
	for i := 0; i < 5; i++ {
		t := mask & (x[i] ^ y[i])
		x[i] ^= t
		y[i] ^= t
	}
}

func x25519(scalar, uIn *[32]byte) [32]byte {
	var k [32]byte
	copy(k[:], scalar[:])
	clampScalar(&k)

	var u fieldElement
	feFromBytes(&u, uIn)

	x2 := feOne()
	z2 := feZero()
	x3 := u
	z3 := feOne()

	feA24 := fieldElement{121665}

	var swap uint64

	for t := 254; t >= 0; t-- {
		kt := uint64((k[t/8] >> uint(t%8)) & 1)
		swap ^= kt
		cswap(&x2, &x3, swap)
		cswap(&z2, &z3, swap)
		swap = kt

		var A, AA, B, BB, E, C, D, DA, CB fieldElement

		feAdd(&A, &x2, &z2)
		feSquare(&AA, &A)
		feSub(&B, &x2, &z2)
		feSquare(&BB, &B)
		feSub(&E, &AA, &BB)
		feAdd(&C, &x3, &z3)
		feSub(&D, &x3, &z3)
		feMul(&DA, &D, &A)
		feMul(&CB, &C, &B)

		var dapcb, damcb fieldElement
		feAdd(&dapcb, &DA, &CB)
		feSub(&damcb, &DA, &CB)
		feSquare(&x3, &dapcb)
		feSquare(&damcb, &damcb)
		feMul(&z3, &u, &damcb)

		feMul(&x2, &AA, &BB)

		var t0 fieldElement
		feMul(&t0, &feA24, &E)
		feAdd(&t0, &AA, &t0)
		feMul(&z2, &E, &t0)
	}

	cswap(&x2, &x3, swap)
	cswap(&z2, &z3, swap)

	var zInv, result fieldElement
	feInvert(&zInv, &z2)
	feMul(&result, &x2, &zInv)

	var out [32]byte
	feToBytes(&out, &result)
	return out
}
