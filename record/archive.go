// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package record

// ArchiveFile is a mapping between an archive file and all of the files it
// directly contains. The entries themselves may also have an associated
// ArchiveFile instance, but that is not tracked in this structure.
type ArchiveFile struct {
	File            *File   `yaml:",omitempty"`
	Entries         []*File `yaml:",omitempty"`
	embeddedCacheID `yaml:"-"`
}

// SerializedArchiveFile is an alternative representation of ArchiveFile that
// uses uint64 keys instead of pointers
type SerializedArchiveFile struct {
	ID      uint64
	File    uint64
	Entries []uint64
}
