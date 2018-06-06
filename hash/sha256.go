// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package hash

import (
	"crypto/sha256"
	"hash"
)

type SHA256Digest struct{ digest256 }

func (SHA256Digest) TypeName() string {
	return "sha256"
}

type SHA256Hasher struct {
	BasicHasher
}

func (sha256 SHA256Digest) SRI() string {
	return fmtSRI("sha256", sha256.digest256[:])
}

func NewSHA256Digest(h hash.Hash) SHA256Digest {
	d := SHA256Digest{}
	h.Sum(d.digest256[:0])
	return d
}

func newSHA256Digest(h hash.Hash) Digest {
	return NewSHA256Digest(h)
}

// NewSHA256Hasher creates a new async hasher for generating sha256sums
func NewSHA256Hasher() SHA256Hasher {
	h := SHA256Hasher{}
	newBasicHasher(&h.BasicHasher, sha256.New(), newSHA256Digest)
	return h
}
