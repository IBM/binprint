// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package hash

import (
	"hash"

	"github.com/minio/highwayhash"
)

// HighwayHash is a super fast collission resistant hashing algorithm
// specifically optimized to take advantage of SIMD instructions on modern
// processors. It is not considered a cryptographic hash because it is so fast,
// thus making brute-forcing it too easy. However, in cases where the only
// adversary is randomness, such as a multi-hash based identification system,
// the speed is a huge advantage.
//
// More information:
//  - https://github.com/google/highwayhash
//  - https://en.wikipedia.org/wiki/HighwayHash
//  - https://blog.minio.io/highwayhash-fast-hashing-at-over-10-gb-s-per-core-in-golang-fee938b5218a
//  - https://github.com/minio/highwayhash

// BinprintHighwayKey is the hashing key used by all binprint hashes calculated with the Highway Hash algorithm
var BinprintHighwayKey = []byte{0xed, 0x73, 0xad, 0xab, 0x57, 0xd, 0x4f, 0x16, 0xc8, 0xd0, 0xa8, 0xac, 0x81, 0x47, 0x4a, 0xe3, 0xd5, 0xf8, 0x7f, 0x8, 0x7d, 0xfd, 0xcb, 0x91, 0x90, 0x94, 0x3a, 0x66, 0xfd, 0xf0, 0x40, 0xd6}

// ********* Highway64

type Highway64Digest struct{ digest64 }

var _ Digest = Highway64Digest{}

func (Highway64Digest) TypeName() string {
	return "highway64bp"
}
func (d Highway64Digest) SRI() string {
	return fmtSRI("highway64bp", d.digest64[:])
}

func NewHighway64Digest(h hash.Hash) Highway64Digest {
	d := Highway64Digest{}
	h.Sum(d.digest64[:0])
	return d
}

func newHighway64Digest(h hash.Hash) Digest {
	return NewHighway64Digest(h)
}

// Highway64Hasher implements HighwayHash64 using the AsyncHasher interface, which is a superset of the hash.Hash interface
type Highway64Hasher struct {
	BasicHasher
}

func (h Highway64Hasher) Sum64() uint64 {
	return h.BasicHasher.Hash.(hash.Hash64).Sum64()
}

func NewHighway64Hasher() Highway64Hasher {
	hasher := Highway64Hasher{}
	hash, _ := highwayhash.New64(BinprintHighwayKey)
	newBasicHasher(&hasher.BasicHasher, hash, newHighway64Digest)
	return hasher
}

// ********* Highway128

type Highway128Digest struct{ digest128 }

var _ Digest = Highway128Digest{}

func (Highway128Digest) TypeName() string {
	return "highway128bp"
}
func (d Highway128Digest) SRI() string {
	return fmtSRI("highway128bp", d.digest128[:])
}

func NewHighway128Digest(h hash.Hash) Highway128Digest {
	d := Highway128Digest{}
	h.Sum(d.digest128[:0])
	return d
}

func newHighway128Digest(h hash.Hash) Digest {
	return NewHighway128Digest(h)
}

type Highway128Hasher struct {
	BasicHasher
}

func NewHighway128Hasher() Highway128Hasher {
	hasher := Highway128Hasher{}
	hash, _ := highwayhash.New128(BinprintHighwayKey)
	newBasicHasher(&hasher.BasicHasher, hash, newHighway128Digest)
	return hasher
}

// ********* Highway256

type Highway256Digest struct{ digest256 }

var _ Digest = Highway256Digest{}

func (Highway256Digest) TypeName() string {
	return "highway256bp"
}
func (d Highway256Digest) SRI() string {
	return fmtSRI("highway256bp", d.digest256[:])
}

func NewHighway256Digest(h hash.Hash) Highway256Digest {
	d := Highway256Digest{}
	h.Sum(d.digest256[:0])
	return d
}

func newHighway256Digest(h hash.Hash) Digest {
	return NewHighway256Digest(h)
}

type Highway256Hasher struct {
	BasicHasher
}

func NewHighway256Hasher() Highway256Hasher {
	hasher := Highway256Hasher{}
	hash, _ := highwayhash.New(BinprintHighwayKey)
	newBasicHasher(&hasher.BasicHasher, hash, newHighway256Digest)
	return hasher
}
