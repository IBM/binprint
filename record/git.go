// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package record

import (
	"fmt"

	"github.com/IBM/binprint/hash"
)

// GitRepoSource is a container representation of a git commit of a repository
type GitRepoSource struct {
	Commit          hash.GitShaDigest
	Tag             string  `yaml:",omitempty"`
	Branch          string  `yaml:",omitempty"`
	URL             string  `yaml:",omitempty"`
	Files           []*File `yaml:",omitempty"`
	embeddedCacheID `yaml:"-"`
}

// SerializedGitRepo is an alternative form of GitRepoSource that uses numeric IDs instead of pointers
type SerializedGitRepo struct {
	ID     uint64
	Commit hash.GitShaDigest
	Tag    string   `yaml:",omitempty"`
	Branch string   `yaml:",omitempty"`
	URL    string   `yaml:",omitempty"`
	Files  []uint64 `yaml:",omitempty"`
}

// URN is a self-describing unique identifier for a specific commit of a
// specific repository.
func (r GitRepoSource) URN() string {
	return fmt.Sprintf("urn:x-fp:git:%s:%s:%s", r.Commit.String(), r.Branch, r.Tag)
}

// Find returns a list of Files contained in the git repo that match the
// provided fingerprint.
func (r GitRepoSource) Find(i *Fingerprint) []*File {
	hits := []*File{}
	for _, f := range r.Files {
		// log.Printf("Comparing %s to %s\n", f.Name(), i.Name())
		if f.Is(i) {
			hits = append(hits, f)
		}
	}
	return hits
}

// RecordBlob records the given file as being part of this repo@commit
func (r *GitRepoSource) RecordBlob(f *File) {
	r.Files = append(r.Files, f)
}
