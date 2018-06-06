// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package hash

import (
	"crypto/md5"
	"hash"
)

type MD5Digest struct{ digest128 }

func (MD5Digest) TypeName() string {
	return "md5"
}

type MD5Hasher struct {
	BasicHasher
}

func (md5 MD5Digest) SRI() string {
	return fmtSRI("md5", md5.digest128[:])
}

func NewMD5Digest(h hash.Hash) MD5Digest {
	d := MD5Digest{}
	h.Sum(d.digest128[:0])
	return d
}

func newMD5Digest(h hash.Hash) Digest {
	return NewMD5Digest(h)
}

// NewMD5Hasher creates a new async hasher for generating md5sums
func NewMD5Hasher() MD5Hasher {
	h := MD5Hasher{}
	newBasicHasher(&h.BasicHasher, md5.New(), newMD5Digest)
	return h
}
