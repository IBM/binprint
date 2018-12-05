// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"github.com/IBM/binprint/record"
	"github.com/IBM/binprint/store"
)

var cache = store.NewInMemoryStore()

// PersistRememberedObjects persists the in-memory store to disk for
// resuscitation in future runs.
func PersistRememberedObjects() {
	cache.PersistRememberedObjects()
}

// GetStore returns the current backing store being used
func GetStore() record.Store {
	return cache
}

// RestoreRememberedObjects loads a previously persisted dump of the in-memory
// store in to memory so that previous work does not need to be repeated.
func RestoreRememberedObjects() {
	if populated := store.RestoreRememberedObjects(); populated != nil {
		cache = populated
	}
}

// FindMatchingFingerprint searches the in-memory database for the first fingerprint that matches the provided FingerprintMatcher
func FindMatchingFingerprint(matcher FingerprintMatcher) *record.Fingerprint {

	// If we are looking for a full gitsha then we can just do a direct lookup without scanning
	if matcher.T == "git" || matcher.T == "gitsha" {
		if len(matcher.B) == 20 {
			exact := [20]byte{}
			copy(exact[:], matcher.B)
			// // var exact [20]byte =
			// exact := [...]byte{...matcher.B} // hash.NewGitShaDigestFromBytes(matcher.B)
			return cache.GetFingerprintByGitSHA(exact)
		}
	}

	matchFn := func(fp *record.Fingerprint) bool {
		return matcher.Match(fp)
	}
	return cache.FindMatchingFingerprint(matchFn)
}
