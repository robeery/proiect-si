package ecdh

import "math/bits"

// fieldElement is an element of GF(2^255-19) in radix-2^51:
//
//	val = f[0] + f[1]*2^51 + f[2]*2^102 + f[3]*2^153 + f[4]*2^204
type fieldElement [5]uint64

const mask51 uint64 = (1 << 51) - 1

type uint128 struct{ hi, lo uint64 }

func add128(a uint128, bhi, blo uint64) uint128 {
	lo, carry := bits.Add64(a.lo, blo, 0)
	hi, _ := bits.Add64(a.hi, bhi, carry)
	return uint128{hi, lo}
}

func feAdd(out, a, b *fieldElement) {
	out[0] = a[0] + b[0]
	out[1] = a[1] + b[1]
	out[2] = a[2] + b[2]
	out[3] = a[3] + b[3]
	out[4] = a[4] + b[4]
}

// feSub sets out = a - b, adding 2*p first to prevent underflow.
func feSub(out, a, b *fieldElement) {
	const twoP0 = 2 * ((1 << 51) - 19)
	const twoP1 = 2 * ((1 << 51) - 1)
	out[0] = twoP0 + a[0] - b[0]
	out[1] = twoP1 + a[1] - b[1]
	out[2] = twoP1 + a[2] - b[2]
	out[3] = twoP1 + a[3] - b[3]
	out[4] = twoP1 + a[4] - b[4]
}

func feReduce(a *fieldElement) {
	for pass := 0; pass < 2; pass++ {
		carry := a[0] >> 51
		a[0] &= mask51
		a[1] += carry

		carry = a[1] >> 51
		a[1] &= mask51
		a[2] += carry

		carry = a[2] >> 51
		a[2] &= mask51
		a[3] += carry

		carry = a[3] >> 51
		a[3] &= mask51
		a[4] += carry

		carry = a[4] >> 51
		a[4] &= mask51
		a[0] += carry * 19 // 2^255 ≡ 19 mod p
	}
}

func feMul(out, a, b *fieldElement) {
	b1_19 := b[1] * 19
	b2_19 := b[2] * 19
	b3_19 := b[3] * 19
	b4_19 := b[4] * 19

	var c0 uint128
	hi, lo := bits.Mul64(a[0], b[0])
	c0 = add128(c0, hi, lo)
	hi, lo = bits.Mul64(a[1], b4_19)
	c0 = add128(c0, hi, lo)
	hi, lo = bits.Mul64(a[2], b3_19)
	c0 = add128(c0, hi, lo)
	hi, lo = bits.Mul64(a[3], b2_19)
	c0 = add128(c0, hi, lo)
	hi, lo = bits.Mul64(a[4], b1_19)
	c0 = add128(c0, hi, lo)

	var c1 uint128
	hi, lo = bits.Mul64(a[0], b[1])
	c1 = add128(c1, hi, lo)
	hi, lo = bits.Mul64(a[1], b[0])
	c1 = add128(c1, hi, lo)
	hi, lo = bits.Mul64(a[2], b4_19)
	c1 = add128(c1, hi, lo)
	hi, lo = bits.Mul64(a[3], b3_19)
	c1 = add128(c1, hi, lo)
	hi, lo = bits.Mul64(a[4], b2_19)
	c1 = add128(c1, hi, lo)

	var c2 uint128
	hi, lo = bits.Mul64(a[0], b[2])
	c2 = add128(c2, hi, lo)
	hi, lo = bits.Mul64(a[1], b[1])
	c2 = add128(c2, hi, lo)
	hi, lo = bits.Mul64(a[2], b[0])
	c2 = add128(c2, hi, lo)
	hi, lo = bits.Mul64(a[3], b4_19)
	c2 = add128(c2, hi, lo)
	hi, lo = bits.Mul64(a[4], b3_19)
	c2 = add128(c2, hi, lo)

	var c3 uint128
	hi, lo = bits.Mul64(a[0], b[3])
	c3 = add128(c3, hi, lo)
	hi, lo = bits.Mul64(a[1], b[2])
	c3 = add128(c3, hi, lo)
	hi, lo = bits.Mul64(a[2], b[1])
	c3 = add128(c3, hi, lo)
	hi, lo = bits.Mul64(a[3], b[0])
	c3 = add128(c3, hi, lo)
	hi, lo = bits.Mul64(a[4], b4_19)
	c3 = add128(c3, hi, lo)

	var c4 uint128
	hi, lo = bits.Mul64(a[0], b[4])
	c4 = add128(c4, hi, lo)
	hi, lo = bits.Mul64(a[1], b[3])
	c4 = add128(c4, hi, lo)
	hi, lo = bits.Mul64(a[2], b[2])
	c4 = add128(c4, hi, lo)
	hi, lo = bits.Mul64(a[3], b[1])
	c4 = add128(c4, hi, lo)
	hi, lo = bits.Mul64(a[4], b[0])
	c4 = add128(c4, hi, lo)

	carry0 := c0.hi<<13 | c0.lo>>51
	r0 := c0.lo & mask51

	c1 = add128(c1, 0, carry0)
	carry1 := c1.hi<<13 | c1.lo>>51
	r1 := c1.lo & mask51

	c2 = add128(c2, 0, carry1)
	carry2 := c2.hi<<13 | c2.lo>>51
	r2 := c2.lo & mask51

	c3 = add128(c3, 0, carry2)
	carry3 := c3.hi<<13 | c3.lo>>51
	r3 := c3.lo & mask51

	c4 = add128(c4, 0, carry3)
	carry4 := c4.hi<<13 | c4.lo>>51
	r4 := c4.lo & mask51

	r0 += carry4 * 19
	carry0 = r0 >> 51
	r0 &= mask51
	r1 += carry0

	out[0] = r0
	out[1] = r1
	out[2] = r2
	out[3] = r3
	out[4] = r4
}

func feSquare(out, a *fieldElement) { feMul(out, a, a) }

// feInvert sets out = z^(p-2) mod p using the addition chain for p-2 = 2^255-21.
func feInvert(out, z *fieldElement) {
	var z2, z9, z11, z_5_0, z_10_0, z_20_0, z_50_0, z_100_0, tmp fieldElement

	feSquare(&z2, z)
	feSquare(&tmp, &z2)
	feSquare(&tmp, &tmp)
	feMul(&z9, &tmp, z)
	feMul(&z11, &z9, &z2)
	feSquare(&tmp, &z11)
	feMul(&z_5_0, &tmp, &z9)

	feSquare(&tmp, &z_5_0)
	for i := 1; i < 5; i++ {
		feSquare(&tmp, &tmp)
	}
	feMul(&z_10_0, &tmp, &z_5_0)

	feSquare(&tmp, &z_10_0)
	for i := 1; i < 10; i++ {
		feSquare(&tmp, &tmp)
	}
	feMul(&z_20_0, &tmp, &z_10_0)

	feSquare(&tmp, &z_20_0)
	for i := 1; i < 20; i++ {
		feSquare(&tmp, &tmp)
	}
	feMul(&tmp, &tmp, &z_20_0)

	feSquare(&tmp, &tmp)
	for i := 1; i < 10; i++ {
		feSquare(&tmp, &tmp)
	}
	feMul(&z_50_0, &tmp, &z_10_0)

	feSquare(&tmp, &z_50_0)
	for i := 1; i < 50; i++ {
		feSquare(&tmp, &tmp)
	}
	feMul(&z_100_0, &tmp, &z_50_0)

	feSquare(&tmp, &z_100_0)
	for i := 1; i < 100; i++ {
		feSquare(&tmp, &tmp)
	}
	feMul(&tmp, &tmp, &z_100_0)

	feSquare(&tmp, &tmp)
	for i := 1; i < 50; i++ {
		feSquare(&tmp, &tmp)
	}
	feMul(&tmp, &tmp, &z_50_0)

	for i := 0; i < 5; i++ {
		feSquare(&tmp, &tmp)
	}
	feMul(out, &tmp, &z11)
}

func feFromBytes(out *fieldElement, b *[32]byte) {
	load8 := func(off int) uint64 {
		var v uint64
		for i := 0; i < 8 && off+i < 32; i++ {
			v |= uint64(b[off+i]) << (8 * uint(i))
		}
		return v
	}

	var tmp [32]byte
	copy(tmp[:], b[:])
	tmp[31] &= 0x7F
	b = &tmp

	out[0] = load8(0) & mask51
	out[1] = (load8(6) >> 3) & mask51
	out[2] = (load8(12) >> 6) & mask51
	out[3] = (load8(19) >> 1) & mask51
	out[4] = (load8(25) >> 4) & mask51
}

func feToBytes(out *[32]byte, f *fieldElement) {
	h := *f
	feReduce(&h)

	const p0lim = mask51 - 18
	var t [5]uint64
	var borrow uint64
	t[0], borrow = bits.Sub64(h[0], p0lim, 0)
	t[1], borrow = bits.Sub64(h[1], mask51, borrow)
	t[2], borrow = bits.Sub64(h[2], mask51, borrow)
	t[3], borrow = bits.Sub64(h[3], mask51, borrow)
	t[4], borrow = bits.Sub64(h[4], mask51, borrow)

	sel := uint64(0) - borrow
	h[0] = (h[0] & sel) | (t[0] & ^sel)
	h[1] = (h[1] & sel) | (t[1] & ^sel)
	h[2] = (h[2] & sel) | (t[2] & ^sel)
	h[3] = (h[3] & sel) | (t[3] & ^sel)
	h[4] = (h[4] & sel) | (t[4] & ^sel)

	w0 := h[0] | h[1]<<51
	w1 := h[1]>>13 | h[2]<<38
	w2 := h[2]>>26 | h[3]<<25
	w3 := h[3]>>39 | h[4]<<12

	out[0] = byte(w0)
	out[1] = byte(w0 >> 8)
	out[2] = byte(w0 >> 16)
	out[3] = byte(w0 >> 24)
	out[4] = byte(w0 >> 32)
	out[5] = byte(w0 >> 40)
	out[6] = byte(w0 >> 48)
	out[7] = byte(w0 >> 56)

	out[8] = byte(w1)
	out[9] = byte(w1 >> 8)
	out[10] = byte(w1 >> 16)
	out[11] = byte(w1 >> 24)
	out[12] = byte(w1 >> 32)
	out[13] = byte(w1 >> 40)
	out[14] = byte(w1 >> 48)
	out[15] = byte(w1 >> 56)

	out[16] = byte(w2)
	out[17] = byte(w2 >> 8)
	out[18] = byte(w2 >> 16)
	out[19] = byte(w2 >> 24)
	out[20] = byte(w2 >> 32)
	out[21] = byte(w2 >> 40)
	out[22] = byte(w2 >> 48)
	out[23] = byte(w2 >> 56)

	out[24] = byte(w3)
	out[25] = byte(w3 >> 8)
	out[26] = byte(w3 >> 16)
	out[27] = byte(w3 >> 24)
	out[28] = byte(w3 >> 32)
	out[29] = byte(w3 >> 40)
	out[30] = byte(w3 >> 48)
	out[31] = byte(w3 >> 56)
}

func feOne() fieldElement  { return fieldElement{1} }
func feZero() fieldElement { return fieldElement{} }
