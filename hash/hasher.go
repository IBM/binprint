// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package hash

import (
	"hash"
	"io"
)

// AsyncHash is a wrapper for hash.Hash that operates asynchronously
// by using a buffering pipe to accept input and a channel to provide
// the final digest
type AsyncHash interface {
	hash.Hash
	io.Closer
	Digest() Digest
	Done() <-chan Digest
}

// // func hashCh(h hash.Hash) (io.WriteCloser, chan []byte) {
// // 	ch := make(chan []byte, 0)
// // 	r, w := io.Pipe()
// // 	go func() {
// // 		defer r.Close()
// // 		if _, err := io.Copy(h, r); err != nil {
// // 			log.Fatal(err)
// // 		}
// // 		ch <- h.Sum(nil)
// // 	}()
// // 	return w, ch
// // }

// // func multiCopyClose(r io.Reader, writers ...io.Writer) (int64, error) {
// // 	for _, mwc := range writers {
// // 		if c, isCloser := mwc.(io.Closer); isCloser {
// // 			defer c.Close()
// // 		}
// // 	}
// // 	w := io.MultiWriter(writers...)
// // 	return io.Copy(w, r)
// // }

// func asyncHashSum(r io.Reader, hasher hash.Hash) (io.Reader, <-chan error) {
// 	errChannel := make(chan error, 1)

// 	// if _, ok := r.(passthroughHasher); ok {
// 	// 	panic("nested passthrough hasher!")
// 	// }

// 	if r == nil {
// 		panic("nil reader? seriously?")
// 	}

// 	readerToHash, hashWriter := io.Pipe()
// 	wrapRead, wrapWrite := io.Pipe()
// 	// like TeeReader except we close the writer when we read io.EOF
// 	go func() {
// 		defer hashWriter.Close()
// 		defer wrapWrite.Close()
// 		mw := io.MultiWriter(hashWriter, wrapWrite)
// 		n, err := io.Copy(mw, r)
// 		if err != nil {
// 			log.Println("Bytes read in passthrough: ", n)
// 			log.Println("io error in passthrough:", err)
// 		} else {
// 			// log.Println("Bytes read in passthrough: ", n)
// 		}
// 	}()
// 	go func() {
// 		defer close(errChannel)
// 		_, err := io.Copy(hasher, readerToHash)
// 		errChannel <- err
// 	}()

// 	// we use this un-exported type wrapper to detect recursive wrapping
// 	passthroughReader := wrapRead

// 	return passthroughReader, errChannel
// }
