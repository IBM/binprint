// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package record

// File represents a fingerprinted file by mapping a Path string to a
// Fingerprint.
type File struct {
	Path        string
	Fingerprint *Fingerprint `yaml:"hashes,omitempty"`
	// cache       embeddedCacheID
	embeddedCacheID `yaml:"-"`
}

// SerializedFile is an alternative representation of ArchiveFile that uses
// uint64 keys instead of pointers.
type SerializedFile struct {
	ID          uint64
	Path        string
	Fingerprint uint64
}

// Is implements the FingerprintMather interface allowing a File to be compared
// to another object such as a Fingerprint or another File.
func (f File) Is(other interface{}) bool {
	var of *File
	// log.Println("is %s:%s == %s:%s?", f.Name(), f.GitSha1sum.String(), other.Name(), other.(File).GitSha1sum.String())
	switch o := other.(type) {
	case Fingerprint, *Fingerprint:
		return f.Fingerprint.Is(other)
	case File:
		of = &o
	case *File:
		of = o
	default:
		return false
	}

	return f.Fingerprint.Is(of.Fingerprint) && f.Path == of.Path
}

func (f File) String() string {
	prefix := "  "
	if f.IsCached() {
		prefix = "* "
	}
	return prefix + f.Path + ": " + f.Fingerprint.GitSHA.String()
}

// SRI returns a subresource integrity string for the file. See Fingerprint.SRI.
func (f File) SRI() string {
	return f.Fingerprint.SRI()
}
