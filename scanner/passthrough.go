// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"io"
	"os"

	"github.com/IBM/binprint/record"
)

// we use this un-exported type wrapper to detect recursive wrapping
type passthroughHasher struct {
	*io.PipeReader
}

func fingerprintPassthrough(r io.Reader, size int64, stat os.FileInfo) (io.Reader, <-chan *record.Fingerprint) {
	fpResult := make(chan *record.Fingerprint, 1)
	// if r = nil {
	// 	fpResult <- nil
	// 	close(fpResult)
	// 	return r, fpResult
	// }
	if _, ok := r.(passthroughHasher); ok {
		panic("nested passthrough hasher!")
	}

	if r == nil {
		panic("nil reader? seriously?")
	}

	if stat != nil {
		cfp := cache.GetStatFingerprint(stat)
		if cfp != nil {
			fpResult <- cfp
			close(fpResult)
			log.Println("skipping passthrough, found cached fingerprint")
			return r, fpResult
		}
	}

	readerToHash, hashWriter := io.Pipe()
	wrapRead, wrapWrite := io.Pipe()
	// like TeeReader except we close the writer when we read io.EOF
	go func() {
		defer hashWriter.Close()
		defer wrapWrite.Close()
		mw := io.MultiWriter(hashWriter, wrapWrite)
		n, err := io.Copy(mw, r)
		if err != nil {
			log.Println("Bytes read in passthrough: ", n)
			log.Println("io error in passthrough:", err)
		} else {
			// log.Println("Bytes read in passthrough: ", n)
		}
	}()
	go func() {
		defer close(fpResult)
		fp := new(record.Fingerprint)
		if err := fp.CalculateSums(readerToHash, size); err != nil {
			panic(err)
		}
		fp = cache.PutFingerprint(fp)
		if stat != nil {
			cache.PutStatFingerprint(stat, fp)
		}
		// CacheStatFingerprint(stat, fp)
		fpResult <- fp
	}()

	// we use this un-exported type wrapper to detect recursive wrapping
	passthroughReader := &passthroughHasher{PipeReader: wrapRead}

	return passthroughReader, fpResult
}
