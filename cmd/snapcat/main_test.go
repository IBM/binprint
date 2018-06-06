// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"testing"
)

func TestPeek(t *testing.T) {
	buf := make([]byte, 1024)
	rand.Read(buf)
	tests := []struct {
		length int
		ask    int
		expect int
	}{
		{0, 0, 0},
		{0, 10, 0},
		{10, 0, 0},
		{1000, 400, 400},
		{500, 1000, 500},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("(%d,%d,%d)", tt.length, tt.ask, tt.expect)
		t.Run(name, func(t *testing.T) {
			rawInput := bytes.NewBuffer(buf[0:tt.length])
			header, peekedReader := Peek(rawInput, tt.ask)
			recombined, err := ioutil.ReadAll(peekedReader)
			if err != nil {
				t.Error("Error reading test data", err)
			}
			if len(header) != tt.expect {
				t.Errorf("Peek() got = %v, want %v", len(header), tt.expect)
			}
			if !bytes.Equal(recombined, buf[0:tt.length]) {
				t.Errorf("Peek() got %v, want %v", recombined, buf[0:tt.length])
			}
		})
	}
}

func TestIsSnappy(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		isSnappy bool
	}{
		{"empty input", []byte{}, false},
		{"short input", []byte{1, 2, 3, 4}, false},
		{"compressed input", []byte("\xff\x06\x00\x00" + "sNaPpY" + "some other stuff"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := bytes.NewBuffer(tt.buf)
			fullInput, isSnappy := IsSnappy(input)
			restoredInput, err := ioutil.ReadAll(fullInput)
			if err != nil {
				t.Error("Error reading test data", err)
			}
			if !bytes.Equal(tt.buf, restoredInput) {
				t.Errorf("IsSnappy() got = %v, want %v", restoredInput, tt.buf)
			}
			if isSnappy != tt.isSnappy {
				t.Errorf("IsSnappy() got1 = %v, want %v", isSnappy, tt.isSnappy)
			}
		})
	}
}

type ClosableBuffer struct{ bytes.Buffer }

func (*ClosableBuffer) Close() error {
	return nil
}

func TestSnapcat(t *testing.T) {
	// 1MB of random data
	definitelyNotSnappy := []byte("prefix that is not the Snappy header so we don't randomly produce a valid Snappy header and fail 0.0000001% of the time")
	randomChunk := make([]byte, 64)
	rand.Read(randomChunk)
	// random data, but repeated for trivial compressability so we can be certain that
	randomBytes := append(definitelyNotSnappy, bytes.Repeat(randomChunk, 64)...)

	randomInput := bytes.NewReader(randomBytes)
	shouldBeCompressed := &ClosableBuffer{}
	if err := Snapcat(randomInput, shouldBeCompressed); err != nil {
		t.Error("Snapcat returned an error while compressing", err)
	}
	if shouldBeCompressed.Len() > len(randomBytes) {
		t.Errorf("Output should be compressed (%d bytes), not larger than input (%d bytes)", shouldBeCompressed.Len(), len(randomBytes))
	}

	compressedInput := bytes.NewReader(shouldBeCompressed.Bytes())
	decompressedOutput := &ClosableBuffer{}
	if err := Snapcat(compressedInput, decompressedOutput); err != nil {
		t.Error("Snapcat returned an error while decompressing", err)
	}
	if !bytes.Equal(decompressedOutput.Bytes(), randomBytes) {
		t.Errorf("Random data did not compress and decompress back to the same data")
	}
}
