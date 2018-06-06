// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"io"

	"github.com/golang/snappy"
	"github.com/ulikunitz/xz/lzma"
	"github.com/xi2/xz"
)

// re: multiple xz dependencies
// github.com/ulikunitz/xz is an xz implementation that provides an API for
// decompressing raw lzma/lzma2 streams.
// github.com/xi2/xz doesn't expose the lzma and lzma2 redaers, but _is_ noticeably
// faster, so we use it for xz
// TODO: submit pull request to github.com/xi2/xz so we can use it for lzma/lzma2 as well

// Decompress returns an io.Reader of the decompressed contents of the given reader
// using the compression method specified by `algo`
func Decompress(algo string, compressedStream io.Reader) (io.Reader, error) {
	switch algo {
	case "xz":
		return xz.NewReader(compressedStream, xz.DefaultDictMax)
	case "lzma":
		log.Print("SLOW PATH: lzma")
		return lzma.NewReader(compressedStream)
	case "lzma2":
		log.Print("SLOW PATH: lzma2")
		return lzma.NewReader2(compressedStream)
	case "gz", "gzip":
		return gzip.NewReader(compressedStream)
	case "bz2", "bzip2":
		return bzip2.NewReader(compressedStream), nil
	case "sz", "snappy":
		return snappy.NewReader(compressedStream), nil
	default:
		return nil, errors.New("Unsupported compression: " + algo)
	}
}
