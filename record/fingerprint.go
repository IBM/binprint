// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package record

import (
	"io"
	"os"
	"strings"

	"github.com/IBM/binprint/hash"
)

// Fingerprint is the core of binprint representing a universally unique (when
// sufficiently populated) identifier for any blob of bytes (typically a file).
type Fingerprint struct {
	GitSHA          hash.GitShaDigest     `yaml:",omitempty"`
	MD5             hash.MD5Digest        `yaml:",omitempty"`
	SHA1            hash.SHA1Digest       `yaml:",omitempty"`
	SHA256          hash.SHA256Digest     `yaml:",omitempty"`
	SHA384          hash.SHA384Digest     `yaml:",omitempty"`
	SHA512          hash.SHA512Digest     `yaml:",omitempty"`
	Hwy64           hash.Highway64Digest  `yaml:",omitempty"`
	Hwy128          hash.Highway128Digest `yaml:",omitempty"`
	Hwy256          hash.Highway256Digest `yaml:",omitempty"`
	Size            int64                 `yaml:",omitempty"`
	embeddedCacheID `yaml:"-"`
}

var self *Fingerprint

// Self returns a Fingerprint of the executable being run. If an error is not
// returned, the all subsequent calls will return the same value without
// re-calculating it.
func Self() (*Fingerprint, error) {
	if self != nil {
		return self, nil
	}

	execPath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	stat, err := os.Stat(execPath)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(execPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fp := new(Fingerprint)
	if err := fp.CalculateSums(file, stat.Size()); err != nil {
		return nil, err
	}
	self = fp

	return self, nil
}

// SerializedFingerprint is a variant of Fingerprint that is suitable for
// serializing with a serialization specific numeric id
type SerializedFingerprint struct {
	ID          uint64
	Fingerprint `yaml:",inline"`
}

// GetDigest returns an existing hash.Digest calculated using the given
// algorithm. If the algorithm is not valid then nil is returned.
func (f Fingerprint) GetDigest(alg string) hash.Digest {
	switch alg {
	case "git", "gitsha":
		return f.GitSHA
	case "sha1":
		return f.SHA1
	case "sha256":
		return f.SHA256
	case "sha384":
		return f.SHA384
	case "sha512":
		return f.SHA512
	case "hwy64bp":
		return f.Hwy64
	case "hwy128bp":
		return f.Hwy128
	case "hwy256bp":
		return f.Hwy256
	default:
		return nil
	}
}

// HasDigest checks if the hash.Digest matches any of the Fingerprint's
// hash.Digests
func (f Fingerprint) HasDigest(other hash.Digest) bool {
	switch o := other.(type) {
	case hash.GitShaDigest:
		return f.GitSHA == o
	// case hash.ShortGitShaDigest:
	// 	return o.Matches(f.GitSHA)
	case hash.MD5Digest:
		return f.MD5 == o
	case hash.SHA1Digest:
		return f.SHA1 == o
	case hash.SHA256Digest:
		return f.SHA256 == o
	case hash.SHA384Digest:
		return f.SHA384 == o
	case hash.SHA512Digest:
		return f.SHA512 == o
	case hash.Highway64Digest:
		return f.Hwy64 == o
	case hash.Highway128Digest:
		return f.Hwy128 == o
	case hash.Highway256Digest:
		return f.Hwy256 == o
	default:
		return false
	}
}

// CalculateSums calculates any sums missing on the Fingerprint using the
// provided io.Reader and given file size. If the given size is <= 0 then a
// gitsha is not calculated. Any sums that are already set (have
// non-zero-values) are not overwritten and their hash is not recalculated or
// verified.
func (f *Fingerprint) CalculateSums(data io.Reader, size int64) error {
	hashers := []hash.AsyncHash{}

	if f.Size == 0 && size != 0 {
		f.Size = size
	}

	// if fp != nil {
	// 	return nil
	// }
	if f.GitSHA.IsZero() && f.Size >= 0 {
		hashers = append(hashers, hash.NewGitShaHasher("blob", f.Size))
	}
	if f.MD5.IsZero() {
		hashers = append(hashers, hash.NewMD5Hasher())
	}
	if f.SHA1.IsZero() {
		hashers = append(hashers, hash.NewSHA1Hasher())
	}
	if f.SHA256.IsZero() {
		hashers = append(hashers, hash.NewSHA256Hasher())
	}
	if f.SHA384.IsZero() {
		hashers = append(hashers, hash.NewSHA384Hasher())
	}
	if f.SHA512.IsZero() {
		hashers = append(hashers, hash.NewSHA512Hasher())
	}
	if f.Hwy64.IsZero() {
		hashers = append(hashers, hash.NewHighway64Hasher())
	}
	if f.Hwy128.IsZero() {
		hashers = append(hashers, hash.NewHighway128Hasher())
	}
	if f.Hwy256.IsZero() {
		hashers = append(hashers, hash.NewHighway256Hasher())
	}

	if len(hashers) == 0 {
		// log.Println("No hash digests missing")
		return nil
	}
	// golang has no generics and the type of a slice is its type, not the container of its elements
	// so even though hash.AsyncHasher satisfies io.Writer, a slice of them is not a slice of io.Writer :-(
	writers := make([]io.Writer, len(hashers))
	for i, h := range hashers {
		writers[i] = h
	}

	// Calculate all the hashes at once!
	hashedLength, err := io.Copy(io.MultiWriter(writers...), data)
	if err != nil {
		log.Debug("Error while copying data to hasher:", err)
		// panic(err)
		// log.Fatal(err)
	}

	// close each hasher to finalize its digest, then store the result
	for _, h := range hashers {
		h.Close()
	}

	for _, h := range hashers {
		if err != nil {
			// we just need to consume
			d := <-h.Done()
			log.Debugf("In error state, dropping hash: %#v\n", d)
			continue
		}
		switch d := (<-h.Done()).(type) {
		case hash.GitShaDigest:
			f.GitSHA = d
		case *hash.GitShaDigest:
			f.GitSHA = *d
		case hash.MD5Digest:
			f.MD5 = d
		case *hash.MD5Digest:
			f.MD5 = *d
		case hash.SHA1Digest:
			f.SHA1 = d
		case *hash.SHA1Digest:
			f.SHA1 = *d
		case hash.SHA256Digest:
			f.SHA256 = d
		case *hash.SHA256Digest:
			f.SHA256 = *d
		case hash.SHA384Digest:
			f.SHA384 = d
		case *hash.SHA384Digest:
			f.SHA384 = *d
		case hash.SHA512Digest:
			f.SHA512 = d
		case *hash.SHA512Digest:
			f.SHA512 = *d
		case hash.Highway64Digest:
			f.Hwy64 = d
		case *hash.Highway64Digest:
			f.Hwy64 = *d
		case hash.Highway128Digest:
			f.Hwy128 = d
		case *hash.Highway128Digest:
			f.Hwy128 = *d
		case hash.Highway256Digest:
			f.Hwy256 = d
		case *hash.Highway256Digest:
			f.Hwy256 = *d
		default:
			log.Debugf("Received unknown digest: %#v\n", d)
		}
	}

	if err == nil && size != 0 && size != hashedLength {
		log.Debugf("Something went horribly wrong. We only hashed %d bytes of %d!", hashedLength, size)
	}
	return err
}

// Is performs a full or partial match against the argument. If the argument is
// another Fingerprint then the fingerprints are considered equivalent if they
// have any matching non-zero digests. If the argument is a digest then it is
// matched against the corresponding digest in the Fingerprint. If the argument
// is a File then a comparison is made against the Fingerprint of that File.
func (f *Fingerprint) Is(other interface{}) bool {
	var of *Fingerprint
	// log.Println("is %s:%s == %s:%s?", f.Name(), f.GitSHA.String(), other.Name(), other.(File).GitSHA.String())
	switch o := other.(type) {
	case hash.Digest:
		return f.HasDigest(o)
	case Fingerprint:
		of = &o
	case *Fingerprint:
		of = o
	case File:
		of = o.Fingerprint
	case *File:
		of = o.Fingerprint
	default:
		return false
	}

	if f == of {
		return true
	}

	// cheap negative case first
	if f.Size != 0 && of.Size != 0 && f.Size != of.Size {
		return false
	}
	if !f.GitSHA.IsZero() && f.GitSHA == of.GitSHA {
		return true
	}
	// TODO: consider protecting against collissions here by requiring a certain match confidence
	if !f.MD5.IsZero() && f.MD5 == of.MD5 {
		return true
	}
	// ditto
	if !f.Hwy64.IsZero() && f.Hwy64 == of.Hwy64 {
		return true
	}
	if !f.Hwy128.IsZero() && f.Hwy128 == of.Hwy128 {
		return true
	}
	if !f.Hwy256.IsZero() && f.Hwy256 == of.Hwy256 {
		return true
	}
	if !f.SHA1.IsZero() && f.SHA1 == of.SHA1 {
		return true
	}
	if !f.SHA256.IsZero() && f.SHA256 == of.SHA256 {
		return true
	}
	if !f.SHA384.IsZero() && f.SHA384 == of.SHA384 {
		return true
	}
	if !f.SHA512.IsZero() && f.SHA512 == of.SHA512 {
		return true
	}
	return false
}

// SRI returns a string of space separated subresource integrity values, which
// are base64 encoded hashes prefixed with the name of the hash algorithm. This
// multi-value string can be used as-is in the "integrity" attribute of a
// <script> tag so that the browser can perform integrity checks when
// downloading scripts from potentially untrusted 3rd party CDNs. NPM has also
// adopted sha512 SRI values for the "dist.integrity" property in package
// manifests for hosted packages as well as in lock files (package-lock.json,
// npm-shrinkwrap.json). For more information see:
//  - https://w3c.github.io/webappsec-subresource-integrity/
//  - https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
func (f Fingerprint) SRI() string {
	sums := []string{
		// only include the hashes that a browser is at least somewhat likely to support
		f.MD5.SRI(),
		f.SHA1.SRI(),
		f.SHA256.SRI(),
		f.SHA384.SRI(),
		f.SHA512.SRI(),
	}
	return strings.Join(sums, " ")
}

func (f Fingerprint) String() string {
	// TODO: what's a reasonable string representation of a fingerprint consisting of multiple hashes?
	hashes := []string{}
	if !f.GitSHA.IsZero() {
		hashes = append(hashes, "git:"+f.GitSHA.String())
	}
	if !f.MD5.IsZero() {
		hashes = append(hashes, "md5:"+f.MD5.String())
	}
	if !f.SHA1.IsZero() {
		hashes = append(hashes, "sha1:"+f.SHA1.String())
	}
	if !f.SHA256.IsZero() {
		hashes = append(hashes, "sha256:"+f.SHA256.String())
	}
	if !f.SHA384.IsZero() {
		hashes = append(hashes, "sha384:"+f.SHA384.String())
	}
	if !f.SHA512.IsZero() {
		hashes = append(hashes, "sha512:"+f.SHA512.String())
	}
	if !f.Hwy64.IsZero() {
		hashes = append(hashes, "hwy64:"+f.Hwy64.String())
	}
	if !f.Hwy128.IsZero() {
		hashes = append(hashes, "hwy128:"+f.Hwy128.String())
	}
	if !f.Hwy256.IsZero() {
		hashes = append(hashes, "hwy256:"+f.Hwy256.String())
	}
	return strings.Join(hashes, " ")
}

// UpdateWith fills in any digests that are missing with the digests provided by
// `other`. Returns the number of hashes that are copied.
func (f *Fingerprint) UpdateWith(of *Fingerprint) int {
	updates := 0
	if f.Size == 0 && of.Size != 0 {
		f.Size = of.Size
		updates++
	}
	if f.GitSHA.IsZero() && f.GitSHA != of.GitSHA {
		f.GitSHA = of.GitSHA
		updates++
	}
	if f.MD5.IsZero() && f.MD5 != of.MD5 {
		f.MD5 = of.MD5
		updates++
	}
	if f.SHA1.IsZero() && f.SHA1 != of.SHA1 {
		f.SHA1 = of.SHA1
		updates++
	}
	if f.SHA256.IsZero() && f.SHA256 != of.SHA256 {
		f.SHA256 = of.SHA256
		updates++
	}
	if f.SHA384.IsZero() && f.SHA384 != of.SHA384 {
		f.SHA384 = of.SHA384
		updates++
	}
	if f.SHA512.IsZero() && f.SHA512 != of.SHA512 {
		f.SHA512 = of.SHA512
		updates++
	}
	if f.Hwy64.IsZero() && f.Hwy64 != of.Hwy64 {
		f.Hwy64 = of.Hwy64
		updates++
	}
	if f.Hwy128.IsZero() && f.Hwy128 != of.Hwy128 {
		f.Hwy128 = of.Hwy128
		updates++
	}
	if f.Hwy256.IsZero() && f.Hwy256 != of.Hwy256 {
		f.Hwy256 = of.Hwy256
		updates++
	}
	return updates
}
