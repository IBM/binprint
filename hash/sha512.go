// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package hash

import (
	"crypto/sha512"
	"hash"
)

// SHA512Digest is a finalized SHA512 checksum
type SHA512Digest struct{ digest512 }

// TypeName returns the canonical short name of the digest type
func (SHA512Digest) TypeName() string {
	return "sha512"
}

type SHA512Hasher struct {
	BasicHasher
}

func (sha SHA512Digest) SRI() string {
	return fmtSRI("sha512", sha.digest512[:])
}

func NewSHA512Digest(h hash.Hash) SHA512Digest {
	d := SHA512Digest{}
	h.Sum(d.digest512[:0])
	return d
}

func newSHA512Digest(h hash.Hash) Digest {
	return NewSHA512Digest(h)
}

// NewSHA512Hasher creates a new async hasher for generating sha512sums
func NewSHA512Hasher() SHA512Hasher {
	h := SHA512Hasher{}
	newBasicHasher(&h.BasicHasher, sha512.New(), newSHA512Digest)
	return h
}
