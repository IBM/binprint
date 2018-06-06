// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package hash

import (
	"fmt"
	"hash"
	"io"
	"log"
)

// BasicHasher is a hash.AsyncHasher that calculates a sha1sum using
// the same salting mechanism as git does when storing blob objects
type BasicHasher struct {
	hash.Hash
	done        chan Digest
	result      Digest
	r           io.ReadCloser
	w           io.WriteCloser
	bytesHashed int64
}

var _ AsyncHash = &BasicHasher{}

// Done returns a Digest channel, satisfying the AsyncHasher interface
func (sh BasicHasher) Done() <-chan Digest {
	return sh.done
}

// Digest returns the calculated Digest. This consumes the channel returned by
// Done(), but will always return the same Digest afterwards.
func (sh BasicHasher) Digest() Digest {
	// block until the digest is finished
	d, ok := <-sh.Done()
	if ok {
		fmt.Printf("read from channel")
		return d
	}
	fmt.Printf("channel was empty")
	return sh.result
}

// Write adds the given slice to the internal Hash
func (sh BasicHasher) Write(bytes []byte) (int, error) {
	return sh.w.Write(bytes)
}

// Close closes the underlying pipe and finalizes the hash
func (sh BasicHasher) Close() error {
	return sh.w.Close()
}

func newBasicHasher(wrapper *BasicHasher, hasher hash.Hash, digester func(hash.Hash) Digest) {
	wrapper.Hash = hasher
	wrapper.done = make(chan Digest, 0)
	wrapper.r, wrapper.w = io.Pipe()
	go func() {
		defer wrapper.r.Close()
		n, err := io.Copy(wrapper.Hash, wrapper.r)
		if err != nil {
			log.Fatal(err)
		}
		wrapper.bytesHashed = n
		wrapper.result = digester(wrapper.Hash)
		wrapper.done <- wrapper.result
	}()
}
