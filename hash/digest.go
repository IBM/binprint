// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package hash

import (
	"bytes"
	"encoding/ascii85"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"hash"
	"regexp"
	"strings"
)

// Digest is a finalized hash.Hash. It conforms to the hash.Hash interface, but
// it does not support operations that modify the finalized checksum
type Digest interface {
	// A Digest is a hash.Hash that has already been finalized and is
	// essentially a wrapper around the fixed length checksum result
	// hash.Hash
	Sum(b []byte) []byte
	// Reset()
	Size() int
	// BlockSize() int

	// IsZero returns true for Digests that are the zero-value of their type
	// (aka, all 0s)
	IsZero() bool

	// String returns the hex string representing the checksum
	String() string

	// Base64 returns the checksum as a base64 string
	Base64() string

	// Bytes returns the finalized checksum bytes, similar to Sum(), but
	// simplified for hashes that have already been finalized
	Bytes() []byte
}

// digest64 is a finalized 64-bit checksum. In addition to satisfying the Digest
// (and hash.Hash) interface, it also satisfies the hash.Hash64 interface for
// returning the calculated sum as a single uin64
type digest64 [64 / 8]byte

// digest128 is a finalized 128-bit checksum
type digest128 [128 / 8]byte

// digest160 is a finalized 128-bit checksum
type digest160 [160 / 8]byte

// digest256 is a finalized 128-bit checksum
type digest256 [256 / 8]byte

// digest384 is a finalized 128-bit checksum
type digest384 [384 / 8]byte

// digest512 is a finalized 128-bit checksum
type digest512 [512 / 8]byte

// handy for easily implementing IsZero
var zero struct {
	digest64
	digest128
	digest160
	digest256
	digest384
	digest512
}

// let the compiler tell us when any of the digest implementations are
// incomplete even if we don't use them as a Digest instance directly in the
// code anywhere
var _ []Digest = []Digest{digest64{}, digest128{}, digest160{}, digest256{}, digest384{}, digest512{}}
var _ hash.Hash64 = digest64{}

// DigestMatcher is a multi-hash comparison operand allowing Digest objects to be matched against.
type DigestMatcher struct {
	P string
	T string
	B []byte
}

var matcherFormat = regexp.MustCompile("^(\\*|git|gitsha|sha1|sha256|sha384|sha512):([0-9a-fA-F]+)$")

// NewDigestMatcher creates a new DigestMatcher by parsing the provided string
func NewDigestMatcher(pat string) (DigestMatcher, error) {
	dm := DigestMatcher{}
	parts := matcherFormat.FindStringSubmatch(pat)
	if len(parts) < 3 {
		return dm, errors.New("Invalid pattern")
	}
	dm = DigestMatcher{T: parts[1], P: parts[2]}
	// if b, err := base64.StdEncoding.DecodeString(dm.s); err != nil {
	// 	dm.b = b
	// } else
	if b, err := hex.DecodeString(dm.P); err == nil {
		dm.B = b
	}
	return dm, nil
}

// Match compares the DigestMatcher against a given Digest, either by string
// representation or direct byte comparison if the provided string was an even
// number of hex digits.
func (matcher DigestMatcher) Match(hash Digest) bool {
	// if matcher.T != "*" && matcher.T != hash.TypeName() {
	// 	return false
	// }
	if len(matcher.B) > hash.Size() {
		return false
	}
	// Because digests are normally provided in an encoded form that doesn't have
	// a 1 character to 1 byte mapping, the byte representation might not have been
	// possible to accurately generate
	if matcher.B != nil {
		return bytes.HasPrefix(hash.Bytes(), matcher.B)
	}
	// This will only really work with hex encoded digests and even then this case
	// will only be run if we are given an odd number length string
	return strings.HasPrefix(hash.String(), matcher.P)
}

func fmtSRI(prefix string, bytes []byte) string {
	return prefix + "-" + base64.StdEncoding.EncodeToString(bytes)
}

func marshalBinaryArray(d interface{}) ([]byte, error) {
	var b bytes.Buffer
	encoder := gob.NewEncoder(&b)
	err := encoder.Encode(d)
	return b.Bytes(), err
}

// UnmarshalBinaryArray modifies the receiver so it must take a pointer receiver.
func unmarshalBinaryArray(d interface{}, data []byte) error {
	b := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(b)
	return decoder.Decode(d)
}

var marshalYAMLBytes = marshalYAMLBytesHex

func marshalYAMLBytesHex(d Digest) (interface{}, error) {
	return d.String(), nil
}

func marshalYAMLBytesBase64(d Digest) (interface{}, error) {
	return d.Base64(), nil
}

func marshalYAMLBytesBase85(d Digest) (interface{}, error) {
	dst := make([]byte, d.Size()+d.Size()/4)
	len := ascii85.Encode(dst, d.Bytes())
	if len > d.Size() {
		return string(dst[:]), nil
	}
	return nil, errors.New("base85 encoding error")
}

var unmarshalYAMLBytes = unmarshalYAMLBytesHex

func unmarshalYAMLBytesHex(d []byte, unmarshal func(interface{}) error) error {
	var str string

	if err := unmarshal(&str); err != nil {
		return err
	}
	raw, err := hex.DecodeString(str)
	if err != nil {
		return err
	}
	copy(d, raw)
	return nil
}

func unmarshalYAMLBytesBase64(d []byte, unmarshal func(interface{}) error) error {
	var str string

	if err := unmarshal(&str); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	copy(d, raw)
	return nil
}

func unmarshalYAMLBytesBase85(d []byte, unmarshal func(interface{}) error) error {
	var str string

	if err := unmarshal(&str); err != nil {
		return err
	}
	nDst, nSrc, err := ascii85.Decode(d, []byte(str), true)
	if err != nil {
		return err
	}
	if nDst <= nSrc {
		return errors.New("Error decoding ascii85")
	}
	return nil

}

func (digest64) Write([]byte) (int, error) { defer panic("Unimplemented"); return 0, nil }
func (digest64) Reset()                    { panic("Unimplemented") }
func (digest64) BlockSize() int            { defer panic("Unimplemented"); return 0 }
func (digest64) Size() int                 { return 64 / 8 }
func (d digest64) Sum(in []byte) []byte    { return append(in, d.Bytes()...) }

// Sum64 satisfies the hash.Hash64 interface
func (d digest64) Sum64() uint64  { return binary.LittleEndian.Uint64(d.Bytes()[0:8]) }
func (d digest64) IsZero() bool   { return d == [len(d)]byte{} }
func (d digest64) String() string { return hex.EncodeToString(d[:]) }
func (d digest64) Base64() string { return base64.StdEncoding.EncodeToString(d[:]) }
func (d digest64) Bytes() []byte  { return d[:] }

// func (d digest64) Len() int                          { return len(d) }
func (d digest64) MarshalYAML() (interface{}, error) { return marshalYAMLBytes(d) }
func (d *digest64) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return unmarshalYAMLBytes(d[:], unmarshal)
}
func (d *digest64) MarshalBinary() ([]byte, error) {
	return marshalBinaryArray((*[len(d)]byte)(d))
}
func (d *digest64) UnmarshalBinary(data []byte) error {
	return unmarshalBinaryArray((*[len(d)]byte)(d), data)
}

// Consider removing these from the interface
// func (digest64) TypeName() string { panic("must implement"); return "" }

// func (d digest64) SRI() string    { return fmtSRI(d.TypeName(), d[:]) }

// func (digest128) Write([]byte) (int, error) { defer panic("Unimplemented"); return 0, nil }
// func (digest128) Reset()                    { panic("Unimplemented") }

// func (digest128) BlockSize() int            { defer panic("Unimplemented"); return 0 }
func (d digest128) Size() int            { return len(d) }
func (d digest128) Sum(in []byte) []byte { return append(in, d.Bytes()...) }
func (d digest128) IsZero() bool         { return d == [len(d)]byte{} }
func (d digest128) String() string       { return hex.EncodeToString(d[:]) }
func (d digest128) Base64() string       { return base64.StdEncoding.EncodeToString(d[:]) }
func (d digest128) Bytes() []byte        { return d[:] }

// func (d digest128) Len() int                          { return len(d) }
func (d digest128) MarshalYAML() (interface{}, error) { return marshalYAMLBytes(d) }
func (d *digest128) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return unmarshalYAMLBytes(d[:], unmarshal)
}
func (d *digest128) MarshalBinary() ([]byte, error) {
	return marshalBinaryArray((*[len(d)]byte)(d))
}
func (d *digest128) UnmarshalBinary(data []byte) error {
	return unmarshalBinaryArray((*[len(d)]byte)(d), data)
}

// Consider removing these from the interface
// func (digest128) TypeName() string { panic("must implement"); return "" }

// func (d digest128) SRI() string    { return fmtSRI(d.TypeName(), d[:]) }
func (digest160) Write([]byte) (int, error) { defer panic("Unimplemented"); return 0, nil }
func (digest160) Reset()                    { panic("Unimplemented") }
func (digest160) BlockSize() int            { defer panic("Unimplemented"); return 0 }
func (d digest160) Size() int               { return len(d) }
func (d digest160) Sum(in []byte) []byte    { return append(in, d.Bytes()...) }
func (d digest160) IsZero() bool            { return d == [len(d)]byte{} }
func (d digest160) String() string          { return hex.EncodeToString(d[:]) }
func (d digest160) Base64() string          { return base64.StdEncoding.EncodeToString(d[:]) }
func (d digest160) Bytes() []byte           { return d[:] }

// func (d digest160) Len() int                          { return len(d) }
func (d digest160) MarshalYAML() (interface{}, error) { return marshalYAMLBytes(d) }
func (d *digest160) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return unmarshalYAMLBytes(d[:], unmarshal)
}
func (d *digest160) MarshalBinary() ([]byte, error) {
	return marshalBinaryArray((*[len(d)]byte)(d))
}
func (d *digest160) UnmarshalBinary(data []byte) error {
	return unmarshalBinaryArray((*[len(d)]byte)(d), data)
}

// Consider removing these from the interface
// func (digest160) TypeName() string { panic("must implement"); return "" }

// func (d digest160) SRI() string    { return fmtSRI(d.TypeName(), d[:]) }

func (digest256) Write([]byte) (int, error) { defer panic("Unimplemented"); return 0, nil }
func (digest256) Reset()                    { panic("Unimplemented") }
func (digest256) BlockSize() int            { defer panic("Unimplemented"); return 0 }
func (d digest256) Size() int               { return len(d) }
func (d digest256) Sum(in []byte) []byte    { return append(in, d.Bytes()...) }
func (d digest256) IsZero() bool            { return d == zero.digest256 }
func (d digest256) String() string          { return hex.EncodeToString(d[:]) }
func (d digest256) Base64() string          { return base64.StdEncoding.EncodeToString(d[:]) }
func (d digest256) Bytes() []byte           { return d[:] }

// func (d digest256) Len() int                          { return len(d) }
func (d digest256) MarshalYAML() (interface{}, error) { return marshalYAMLBytes(d) }
func (d *digest256) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return unmarshalYAMLBytes(d[:], unmarshal)
}
func (d *digest256) MarshalBinary() ([]byte, error) {
	return marshalBinaryArray((*[len(d)]byte)(d))
}
func (d *digest256) UnmarshalBinary(data []byte) error {
	return unmarshalBinaryArray((*[len(d)]byte)(d), data)
}

// Consider removing these from the interface
// func (digest256) TypeName() string { panic("must implement"); return "" }

// func (d digest256) SRI() string    { return fmtSRI(d.TypeName(), d[:]) }
func (digest384) Write([]byte) (int, error) { defer panic("Unimplemented"); return 0, nil }
func (digest384) Reset()                    { panic("Unimplemented") }
func (digest384) BlockSize() int            { defer panic("Unimplemented"); return 0 }
func (d digest384) Size() int               { return len(d) }
func (d digest384) Sum(in []byte) []byte    { return append(in, d.Bytes()...) }
func (d digest384) IsZero() bool            { return d == [len(d)]byte{} }
func (d digest384) String() string          { return hex.EncodeToString(d[:]) }
func (d digest384) Base64() string          { return base64.StdEncoding.EncodeToString(d[:]) }
func (d digest384) Bytes() []byte           { return d[:] }

// func (d digest384) Len() int                          { return len(d) }
func (d digest384) MarshalYAML() (interface{}, error) { return marshalYAMLBytes(d) }
func (d *digest384) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return unmarshalYAMLBytes(d[:], unmarshal)
}
func (d *digest384) MarshalBinary() ([]byte, error) {
	return marshalBinaryArray((*[len(d)]byte)(d))
}
func (d *digest384) UnmarshalBinary(data []byte) error {
	return unmarshalBinaryArray((*[len(d)]byte)(d), data)
}

// Consider removing these from the interface
// func (digest384) TypeName() string { panic("must implement"); return "" }

// func (d digest384) SRI() string    { return fmtSRI(d.TypeName(), d[:]) }
func (digest512) Write([]byte) (int, error) { defer panic("Unimplemented"); return 0, nil }
func (digest512) Reset()                    { panic("Unimplemented") }
func (digest512) BlockSize() int            { defer panic("Unimplemented"); return 0 }
func (d digest512) Size() int               { return len(d) }
func (d digest512) Sum(in []byte) []byte    { return append(in, d.Bytes()...) }
func (d digest512) IsZero() bool            { return d == [len(d)]byte{} }
func (d digest512) String() string          { return hex.EncodeToString(d[:]) }
func (d digest512) Base64() string          { return base64.StdEncoding.EncodeToString(d[:]) }
func (d digest512) Bytes() []byte           { return d[:] }

// func (d digest512) Len() int                          { return len(d) }
func (d digest512) MarshalYAML() (interface{}, error) { return marshalYAMLBytes(d) }
func (d *digest512) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return unmarshalYAMLBytes(d[:], unmarshal)
}
func (d *digest512) MarshalBinary() ([]byte, error) {
	return marshalBinaryArray((*[len(d)]byte)(d))
}
func (d *digest512) UnmarshalBinary(data []byte) error {
	return unmarshalBinaryArray((*[len(d)]byte)(d), data)
}

// Consider removing these from the interface
// func (digest512) TypeName() string { panic("must implement"); return "" }

// func (d digest512) SRI() string    { return fmtSRI(d.TypeName(), d[:]) }
