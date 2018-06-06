// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"github.com/IBM/binprint/record"
)

// FindFiles searches for all file records matching the provided fingerprint.
func FindFiles(f *record.Fingerprint) []*record.File {
	return cache.FindFilesWithFingerprint(f)
}

// FindRepos finds all git repo sources (aka, git commits) that contain the provided fingerprint
func FindRepos(fp *record.Fingerprint) []*record.GitRepoSource {
	return cache.FindGitSourcesContainingFingerprint(fp)
}

// FindArchives finds all archives that directly contain a file with the given fingerprint
func FindArchives(fp *record.Fingerprint) []*record.ArchiveFile {
	return cache.FindArchiveFilesContainingFingerprint(fp)
}
