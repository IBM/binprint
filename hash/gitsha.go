// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package hash

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"log"
)

// GitShaDigest is the variant of sha1 used by Git to identify blobs
type GitShaDigest struct{ digest160 }

var _ Digest = GitShaDigest{}
var _ hash.Hash64 = GitShaDigest{}

// func (GitShaDigest) Write([]byte) (int, error) { defer panic("Unimplemented"); return 0, nil }
// func (GitShaDigest) BlockSize() int            { return sha1.BlockSize }
// func (d GitShaDigest) String() string          { return d.Raw.String() }
// func (d GitShaDigest) Base64() string          { return d.Raw.Base64() }
// func (d GitShaDigest) Bytes() []byte           { return d.Raw.Bytes() }
// func (d GitShaDigest) IsZero() bool            { return d.Raw.IsZero() }
// func (GitShaDigest) Reset()                    { panic("Unimplemented") }
// func (d GitShaDigest) Size() int               { return sha1.Size }
// func (d GitShaDigest) Sum(in []byte) []byte    { return d.Raw.Sum(in) }

func (d GitShaDigest) Sum64() uint64 {
	return binary.LittleEndian.Uint64(d.digest160.Bytes()[0:8])
}

func (d GitShaDigest) Raw() [20]byte {
	return d.digest160
}

func GitShaDigestFromRaw(raw [20]byte) GitShaDigest {
	return GitShaDigest{raw}
}

// func (d GitShaDigest) MarshalYAML() (interface{}, error) { return d.Raw.MarshalYAML() }
// func (d *GitShaDigest) UnmarshalYAML(unmarshal func(interface{}) error) error {
// 	return d.Raw.UnmarshalYAML(unmarshal)
// }
// func (d *GitShaDigest) MarshalBinary() ([]byte, error) {
// 	return marshalBinaryArray((*[len(d.Raw)]byte)(&d.Raw))
// }
// func (d *GitShaDigest) UnmarshalBinary(data []byte) error {
// 	return unmarshalBinaryArray((*[len(d.Raw)]byte)(&d.Raw), data)
// }

func NewGitShaDigest(h hash.Hash) *GitShaDigest {
	gitSHA := new(GitShaDigest)
	h.Sum(gitSHA.digest160[:0])
	return gitSHA
}

func newGitShaDigest(h hash.Hash) Digest {
	return NewGitShaDigest(h)
}

// GitShaHasher is a hash.AsyncHasher that calculates a sha1sum using
// the same salting mechanism as git does when storing blob objects
type GitShaHasher struct {
	BasicHasher
	size int64
}

func (gh *GitShaHasher) Done() <-chan Digest {
	maybeDigest := make(chan Digest, 0)
	go func() {
		result := <-gh.done
		if gh.bytesHashed != gh.size {
			log.Printf("Expected %d, hashed %d. Discarding invalid gitsha\n", gh.size, gh.bytesHashed)
			maybeDigest <- nil // NullGitShaDigest
		} else {
			maybeDigest <- result
		}
	}()
	return maybeDigest
}

func (gh *GitShaHasher) Write(bytes []byte) (int, error) {
	return gh.w.Write(bytes)
}

func (gh *GitShaHasher) Close() error {
	return gh.w.Close()
}

// NewGitShaHasher returns a hash.Hash that will compute a variant sha1 digest as though the input was a git blob object
func NewGitShaHasher(oType string, size int64) *GitShaHasher {
	header := bytes.Buffer{}
	// git calculates all hashes using a common format:
	//   <type><SP><length><0>
	// where:
	//   type is a string of the type (blob, tree, etc.)
	//   <SP> is a literal space
	//   length is a string of the decimal representation of the length of the object
	//   <0> is a literal 0 byte (aka, terminating null)
	header.WriteString(fmt.Sprintf("%s %d", oType, size))
	header.WriteByte(0)
	h := GitShaHasher{size: size}
	sha1Hash := sha1.New()
	io.Copy(sha1Hash, &header)
	newBasicHasher(&h.BasicHasher, sha1Hash, newGitShaDigest)
	return &h
}
