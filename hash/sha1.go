// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package hash

import (
	"crypto/sha1"
	"hash"
)

type SHA1Digest struct {
	digest160
}

func (SHA1Digest) TypeName() string {
	return "sha1"
}

// func (SHA1Digest) Write([]byte) (int, error) { defer panic("Unimplemented"); return 0, nil }
// func (SHA1Digest) Reset()                    { panic("Unimplemented") }
// func (SHA1Digest) BlockSize() int            { return sha1.BlockSize }
// func (d SHA1Digest) Size() int               { return sha1.Size }
// func (d SHA1Digest) Sum(in []byte) []byte    { return d.Raw.Sum(in) }
// func (d SHA1Digest) IsZero() bool            { return d.Raw.IsZero() }
// func (d SHA1Digest) String() string          { return d.Raw.String() }
// func (d SHA1Digest) Base64() string          { return d.Raw.Base64() }
// func (d SHA1Digest) Bytes() []byte           { return d.Raw.Bytes() }

type SHA1Hasher struct {
	BasicHasher
}

func (sha1 SHA1Digest) SRI() string {
	return fmtSRI("sha1", sha1.digest160[:])
}

func NewSHA1Digest(h hash.Hash) SHA1Digest {
	d := SHA1Digest{}
	h.Sum(d.digest160[:0])
	return d
}

func newSHA1Digest(h hash.Hash) Digest {
	return NewSHA1Digest(h)
}

// NewSHA1Hasher creates a new async hasher for generating sha1sums
func NewSHA1Hasher() SHA1Hasher {
	h := SHA1Hasher{}
	newBasicHasher(&h.BasicHasher, sha1.New(), newSHA1Digest)
	return h
}
