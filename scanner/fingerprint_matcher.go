// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"fmt"

	"github.com/IBM/binprint/hash"
	"github.com/IBM/binprint/record"
)

// FingerprintMatcher is a search operand for finding a specific Fingerprint. It
// is typically a truncated form of a hex encoded digest, such as "git:561fc183",
// which is more user friendly than the full-length sha1 digest.
type FingerprintMatcher struct {
	hash.DigestMatcher
}

// NewFingerprintMatcher creates a new matcher based on the partial or complete
// hash of the form <algorithm>:<hex>, such as "git:561fc183".
func NewFingerprintMatcher(pat string) (FingerprintMatcher, error) {
	dm, err := hash.NewDigestMatcher(pat)
	return FingerprintMatcher{dm}, err
}

// Match compares the matcher to the given Fingerprint and returns true if the
// given fingerprint satisfies the matcher.
func (matcher FingerprintMatcher) Match(f *record.Fingerprint) bool {
	// TODO: implement hash wildcarding so that "*:561fc183" can be compared to
	// all of the hashes in the Fingerprint for potential match.
	if matcher.T == "*" || matcher.T == "" {
		return false
	}
	digest := f.GetDigest(matcher.T)
	return digest != nil && matcher.DigestMatcher.Match(digest)
}

// IsExact is true for matchers that do not specify a hash algorithm and should
// therefore be compared to all the hashes present in a Fingerprint when
// matching.
func (matcher FingerprintMatcher) IsExact() bool {
	if matcher.T == "*" {
		return false
	}
	return true
}

// String returns an informational string describing the matcher, including
// whether or not it can be optimized for direct Fingerprint comparison or not.
func (matcher FingerprintMatcher) String() string {
	str := fmt.Sprintf("type: %s, pattern:%s, exact: %t, optimized: %t", matcher.T, matcher.P, matcher.IsExact(), matcher.B != nil)
	if matcher.B == nil {
		str += " (NOT byte match optimized due to odd hex string length)"
	}
	return str
}
