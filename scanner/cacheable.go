// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import "github.com/IBM/binprint/record"

type cacheIDAware interface {
	IsCached() bool
	SetCacheID(uint64)
	CacheID() uint64
}

// Let the compiler ensure these types implement the cacheIDAware interface
// even though we don't actually the cacheIDAware interface directly anywhere
var _ cacheIDAware = (*record.Fingerprint)(nil)
var _ cacheIDAware = (*record.File)(nil)
var _ cacheIDAware = (*record.ArchiveFile)(nil)
var _ cacheIDAware = (*record.GitRepoSource)(nil)
