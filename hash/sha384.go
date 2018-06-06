// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package hash

import (
	"crypto/sha512"
	"hash"
)

type SHA384Digest struct{ digest384 }

var nullSHA384Digest SHA384Digest

func (SHA384Digest) TypeName() string {
	return "sha384"
}

type SHA384Hasher struct {
	BasicHasher
}

func (sha384 SHA384Digest) SRI() string {
	return fmtSRI("sha384", sha384.digest384[:])
}

func NewSHA384Digest(h hash.Hash) SHA384Digest {
	d := SHA384Digest{}
	h.Sum(d.digest384[:0])
	return d
}

func newSHA384Digest(h hash.Hash) Digest {
	return NewSHA384Digest(h)
}

// NewSHA384Hasher creates a new async hasher for generating sha384sums
func NewSHA384Hasher() SHA384Hasher {
	h := SHA384Hasher{}
	newBasicHasher(&h.BasicHasher, sha512.New384(), newSHA384Digest)
	return h
}
