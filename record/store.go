// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package record

import "os"

// FingerprintMatcher describes a function which matches a Fingerprint given to it.
type FingerprintMatcher func(*Fingerprint) bool

// Store provides the API to be implemented by a storage backend. A storage
// backend is required for records because of their interconnected nature.
type Store interface {
	GetStatFingerprint(os.FileInfo) *Fingerprint
	PutStatFingerprint(os.FileInfo, *Fingerprint)
	PersistRememberedObjects()
	PutFingerprint(*Fingerprint) *Fingerprint
	GetFingerprintByGitSHA([20]byte) *Fingerprint
	FindMatchingFingerprint(FingerprintMatcher) *Fingerprint
	PutFile(*File) *File
	GetFileByNameAndGitSHA(string, [20]byte) *File
	FindFilesWithFingerprint(*Fingerprint) []*File
	PutGitSource(*GitRepoSource) *GitRepoSource
	FindGitSourceByURN(string) *GitRepoSource
	FindGitSourcesContainingFingerprint(*Fingerprint) []*GitRepoSource
	PutArchiveFile(*ArchiveFile) *ArchiveFile
	GetArchiveFile(*File) *ArchiveFile
	FindArchiveFilesContainingFingerprint(*Fingerprint) []*ArchiveFile
}
