// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

// snapcat is a simple CLI that reads from stdin and writes to stdout. If the
// input is a Snappy compressed stream it is decompressed and written to stdout.
// If the input is not a Snappy compressed stream then it is compressed and
// written to stdout.
package main

import (
	"bytes"
	"io"
	"os"

	"github.com/golang/snappy"
)

// Peek reads a chunk of the given length from the given reader and returns it
// as a slice as well as a *new* Reader that re-combines the header with the
// remainder of the input. The returned slice will be smaller than the requested
// length if the input was too short.
func Peek(input io.Reader, length int) ([]byte, io.Reader) {
	header := make([]byte, length)
	n, err := input.Read(header)
	if err != nil && err != io.EOF {
		panic(err)
	}
	// resize our header slice down to the number of bytes actually read,
	// otherwise it will be padded with 0's out to the requested length.
	header = header[:n]
	fullInput := io.MultiReader(bytes.NewBuffer(header), input)
	return header, fullInput
}

// IsSnappy peeks at the first 10 bytes of input to determine if it is a valid
// Snappy compressed stream or not. Along with the result of this check, a new
// io.Reader is returned that re-combines the header with the body.
func IsSnappy(input io.Reader) (io.Reader, bool) {
	// As per the snappy spec, this is the magic header that is at the start of
	// every valid snappy compressed stream
	snappyMagic := []byte("\xff\x06\x00\x00" + "sNaPpY")
	header, input := Peek(input, len(snappyMagic))
	isSnappy := bytes.Equal(header, snappyMagic)
	return input, isSnappy
}

// Snapcat reads data from the given io.Reader and writes it to the given
// io.WriteCloser. If the input is compressed with Snappy then it is
// decompressed. If the input is not a valid Snappy compressed stream then it is
// compressed with Snappy.
func Snapcat(input io.Reader, output io.WriteCloser) error {
	input, isSnappy := IsSnappy(input)
	if isSnappy {
		input = snappy.NewReader(input)
	} else {
		output = snappy.NewBufferedWriter(output)
	}
	defer output.Close()
	_, err := io.Copy(output, input)
	return err
}

func main() {
	if err := Snapcat(os.Stdin, os.Stdout); err != nil {
		panic(err)
	}
}
