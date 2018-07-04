// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package store

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/hashicorp/golang-lru"
	"github.com/steakknife/bloomfilter"

	"github.com/IBM/binprint/hash"
	"github.com/IBM/binprint/record"
)

// CachedStatFingerprintKey is an opaque key generated from the stat info of a file.
type CachedStatFingerprintKey string

type fingerprintInMemoryCache struct {
	Fingerprints     []*record.Fingerprint
	fingerprintsLock sync.Mutex
	gitSHAIndex      map[hash.GitShaDigest]uint64
	gitSHAFilter     *bloomfilter.Filter
	Files            []*record.File
	filesLock        sync.Mutex
	GitRepoSources   []*record.GitRepoSource
	reposLock        sync.Mutex
	ArchiveFiles     []*record.ArchiveFile
	archivesLock     sync.Mutex
	statCache        *lru.ARCCache
}

// newCachedStatFingerprintKey takes an os.FileInfo to create a unique key based
// on the inode, size, and mtime of the target file
func (v *fingerprintInMemoryCache) newCachedStatFingerprintKey(fileInfo os.FileInfo) CachedStatFingerprintKey {
	stat := fileInfo.Sys().(*syscall.Stat_t)
	str := strconv.FormatInt(stat.Size, 36) + "," + strconv.FormatUint(stat.Ino, 36) + "," + strconv.FormatInt(fileInfo.ModTime().UnixNano(), 36)
	return CachedStatFingerprintKey(str)
}

func (v *fingerprintInMemoryCache) Verify() error {
	v.fingerprintsLock.Lock()
	defer v.fingerprintsLock.Unlock()
	v.filesLock.Lock()
	defer v.filesLock.Unlock()
	v.archivesLock.Lock()
	defer v.archivesLock.Unlock()
	v.reposLock.Lock()
	defer v.reposLock.Unlock()

	// fmt.Printf("\n%#v\n", v)

	// for id := 0; id < len(v.fingerprints); id++ {
	for id := range v.Fingerprints {
		if v.Fingerprints[id].CacheID() != uint64(id) {
			return fmt.Errorf("Incorrect key on fingerprint. Expected %d to be %d", v.Fingerprints[id].CacheID(), id)
		}
	}
	for id := range v.Files {
		// for id := 0; id < len(v.files); id++ {
		// log.Printf("Verifying %s: %d ?= %d\n", v.files[id].Path, v.files[id].CacheID(), id)
		if v.Files[id].CacheID() != uint64(id) {
			return fmt.Errorf("Incorrect key on file. Expected %s id %d to be %d", v.Files[id].Path, v.Files[id].CacheID(), id)
		}
	}

	for id := range v.ArchiveFiles {
		if v.ArchiveFiles[id].CacheID() != uint64(id) {
			return fmt.Errorf("Incorrect key on archive. Expected %d to be %d", v.ArchiveFiles[id].CacheID(), id)
		}
	}

	for id := range v.GitRepoSources {
		if v.GitRepoSources[id].CacheID() != uint64(id) {
			return fmt.Errorf("Incorrect key on git repo. Expected %d to be %d", v.GitRepoSources[id].CacheID(), id)
		}
	}

	return nil
}

// NewInMemoryStore returns a new memory-backed Store that can be used for
// storing fingerprints being scanned. It is valid until the process exits and
// is not automaticall persisted to disk.
func NewInMemoryStore() record.Store {
	return newInMemoryCache()
}

func newInMemoryCache() *fingerprintInMemoryCache {
	// slices have a zero-value that isn't a valid slice
	statCache, err := lru.NewARC(1024 * 1024)
	if err != nil {
		log.Println("Error initializing LRU/ARC cache(2048)")
	}
	cache := fingerprintInMemoryCache{
		Files:          make([]*record.File, 0, 1024),
		Fingerprints:   make([]*record.Fingerprint, 0, 1024),
		gitSHAIndex:    make(map[hash.GitShaDigest]uint64, 100*1024),
		gitSHAFilter:   bloomfilter.NewOptimal(100*1024, 0.000001),
		GitRepoSources: make([]*record.GitRepoSource, 0, 1024),
		ArchiveFiles:   make([]*record.ArchiveFile, 0, 1024),
		statCache:      statCache,
	}
	return &cache
}

// DumpCache identifies root archives in the cache and recursively lists their
// contents to stdout. At the end a summary of the total number of files,
// archives, and their total size is printed.
func (v *fingerprintInMemoryCache) DumpCache() {
	v.fingerprintsLock.Lock()
	defer v.fingerprintsLock.Unlock()
	v.filesLock.Lock()
	defer v.filesLock.Unlock()
	v.archivesLock.Lock()
	defer v.archivesLock.Unlock()
	v.reposLock.Lock()
	defer v.reposLock.Unlock()
	rootArchives := []*record.ArchiveFile{}
outer:
	for _, archive := range v.ArchiveFiles {
		for _, other := range v.ArchiveFiles {
			for _, entry := range other.Entries {
				if archive.File == entry {
					continue outer
				}
			}
		}
		rootArchives = append(rootArchives, archive)
	}
	for _, root := range rootArchives {
		v.DumpArchive(0, root)
	}

	var totalBytes int64
	for _, f := range v.Fingerprints {
		totalBytes += f.Size
	}
	fmt.Printf("Fingerprints: %d\nFiles: %d\nArchives: %d\nBytes: %d\n",
		len(v.Fingerprints), len(v.Files), len(v.ArchiveFiles),
		totalBytes)
}

// DumpArchive recursively lists the contents of the given archive indented by
// the given level.
func (v *fingerprintInMemoryCache) DumpArchive(level int, a *record.ArchiveFile) {
	indent := strings.Repeat("  ", level)
	fmt.Printf("%s%s:         (%s, %s)\n", indent, a.File.Path, a.File.Fingerprint.SHA256.String(), a.File.Fingerprint.GitSHA.String())
entries:
	for _, e := range a.Entries {
		for _, subA := range v.ArchiveFiles {
			if subA.File == e {
				v.DumpArchive(level+1, subA)
				continue entries
			}
		}
		// fmt.Printf("%s  %s      (%s)\n", indent, e.Path, e.GitSHA.String())
	}
}

// GetStatFingerprint returns a pointer to an existing binprint.Fingerprint
// associated with the given key or nil if one does not exist.
func (v *fingerprintInMemoryCache) GetStatFingerprint(stat os.FileInfo) *record.Fingerprint {
	key := v.newCachedStatFingerprintKey(stat)
	if fp, ok := v.statCache.Get(key); ok {
		return fp.(*record.Fingerprint)
		// fingerprint := fp.(*binprint.Fingerprint)
		// v.gitSHAIndex[fingerprint.GitSHA] = fingerprint.CacheID()
		// // v.gitSHAIndex2.Put(fingerprint.GitSHA.Digest160, fingerprint.CacheID())
		// return fingerprint
	}
	return nil
}

func (v *fingerprintInMemoryCache) PutStatFingerprint(stat os.FileInfo, fingerprint *record.Fingerprint) {
	key := v.newCachedStatFingerprintKey(stat)
	v.statCache.Add(key, fingerprint)
}

// PutFingerprint ensures that the given binprint.Fingerprint is stored in
// the in-memory database. If the given fingerprint is already in the database
// the pointer is returned. If the fingerprint is not already in the database
// then it is added. The returned binprint.Fingerprint pointer may or may not
// refer to the same instance as was passed in, but the returned pointer should
// be used after calling PutFingerprint instead of using the previous
// value.
// Intended use is:
//   someFingerprint = PutFingerprint(someFingerprint)
func (v *fingerprintInMemoryCache) PutFingerprint(fp *record.Fingerprint) *record.Fingerprint {
	if fp.IsCached() {
		return fp
	}
	existing := v.GetFingerprintByGitSHA(fp.GitSHA.Raw())

	v.fingerprintsLock.Lock()
	defer v.fingerprintsLock.Unlock()

	if existing == nil {
		for _, efp := range v.Fingerprints {
			if efp.Is(fp) {
				existing = efp
				break
			}
		}
	}

	if existing != nil {
		// TODO: implement some sort of upsert/merge logic so that the stored fingerprint
		// contains all the digests between the new one and an existing match
		existing.UpdateWith(fp)
		return existing
	}

	v.Fingerprints = append(v.Fingerprints, fp)
	id := uint64(len(v.Fingerprints) - 1)
	fp.SetCacheID(id)
	v.gitSHAIndex[fp.GitSHA] = id
	// v.gitSHAIndex2.Put(fp.GitSHA.Digest160, id)

	// fmt.Printf("\nLogging new fingerprint: %#v\n%#v\nsame? %t\n", fp, fpp, fp == fpp)
	// k, err := highwayhash.New64(hash.BinprintHighwayKey)
	// if err != nil {
	// 	panic(err)
	// }
	// k.Write(fp.GitSHA.Bytes())
	// k.Sum(fp.GitSHA.Bytes[:])
	v.gitSHAFilter.Add(fp.GitSHA)
	return fp
}

func (v *fingerprintInMemoryCache) GetFingerprintByGitSHA(gitSHA [20]byte) *record.Fingerprint {
	v.fingerprintsLock.Lock()
	defer v.fingerprintsLock.Unlock()

	gitDigest := hash.GitShaDigestFromRaw(gitSHA)

	// This map gets moderately large, but the main cost is that we're using the
	// full 160 bit SHA1 digest as the key, which is probably not the fastest
	// lookup. To mitigate this we've thrown this bloom filter in front of our
	// lookups so that we can more efficiently return cache misses, which are
	// actually one of our most common operations.
	if !v.gitSHAFilter.Contains(gitDigest) {
		return nil
	}

	// id, ok := v.gitSHAIndex2.Get(gitDigest.Digest160)
	id, ok := v.gitSHAIndex[gitDigest]
	if ok {
		return v.Fingerprints[id]
	}
	// for id := range v.fingerprints {
	// 	if v.fingerprints[id].GitSHA == gitSHA {
	// 		return &v.fingerprints[id]
	// 	}
	// }
	return nil
}

// FindMatchingFingerprint searches the in-memory database for the first fingerprint that matches the provided binprint.FingerprintMatcher
func (v *fingerprintInMemoryCache) FindMatchingFingerprint(matcher record.FingerprintMatcher) *record.Fingerprint {
	v.fingerprintsLock.Lock()
	defer v.fingerprintsLock.Unlock()

	for _, existing := range v.Fingerprints {
		if matcher(existing) {
			return existing
		}
	}

	return nil
}

func (v *fingerprintInMemoryCache) RememberedFingerprintsCount() int {
	v.fingerprintsLock.Lock()
	defer v.fingerprintsLock.Unlock()
	return len(v.Fingerprints)
}

// PutFile ensures that the given binprint.File is stored in the in-memory
// database. If the given binprint.File pointer already points to an instance
// that is in the database it is returned immediately without modification. If
// the file is not already in the database then a new binprint.File object is
// created with a pointer to an in-memory binprint.Fingerprint equivalent to
// the one associated with the provided file. Intended use is:
//   someFile = PutFile(someFile)
func (v *fingerprintInMemoryCache) PutFile(f *record.File) *record.File {
	if f == nil {
		panic("Can't remember a nil file")
	}
	if f.Fingerprint == nil {
		panic("Can't remember a file with a nil fingerprint")
	}
	if f.IsCached() {
		return f
	}
	v.filesLock.Lock()
	defer v.filesLock.Unlock()

	for _, existing := range v.Files {
		// path match and either points to the same Fingerprint or points to an equivalent Fingerprint
		if existing.Path == f.Path && (f.Fingerprint == existing.Fingerprint || existing.Fingerprint.Is(f.Fingerprint)) {
			return existing
		}
	}
	f.Fingerprint = v.PutFingerprint(f.Fingerprint)
	v.Files = append(v.Files, f)
	id := uint64(len(v.Files) - 1)
	f.SetCacheID(id)
	return f
}

// GetFileByNameAndGitSHA searches the in-memory database for a binprint.File with a
// matching path and gitsha and returns the first match. If no matches are found
// then nil is returned.
func (v *fingerprintInMemoryCache) GetFileByNameAndGitSHA(path string, rawGitsha [20]byte) *record.File {
	v.filesLock.Lock()
	defer v.filesLock.Unlock()

	gitsha := hash.GitShaDigestFromRaw(rawGitsha)

	for _, existing := range v.Files {
		if existing.Path == path && existing.Fingerprint.GitSHA == gitsha {
			return existing
		}
	}
	return nil
}

func (v *fingerprintInMemoryCache) FindFilesWithFingerprint(fp *record.Fingerprint) []*record.File {
	fp = v.GetFingerprintByGitSHA(fp.GitSHA.Raw())
	if fp == nil {
		return nil
	}
	v.filesLock.Lock()
	defer v.filesLock.Unlock()
	matches := []*record.File{}
	for f := range v.Files {
		if v.Files[f].Fingerprint == fp {
			matches = append(matches, v.Files[f])
		}
	}
	return matches
}

func (v *fingerprintInMemoryCache) RememberedFilesCount() int {
	v.filesLock.Lock()
	defer v.filesLock.Unlock()
	return len(v.Files)
}

func (v *fingerprintInMemoryCache) PutGitSource(r *record.GitRepoSource) *record.GitRepoSource {
	v.reposLock.Lock()
	defer v.reposLock.Unlock()
	for id := range v.GitRepoSources {
		if v.GitRepoSources[id].URN() == r.URN() {
			return v.GitRepoSources[id]
		}
	}
	rememberedFiles := make([]*record.File, len(r.Files))
	for i, f := range r.Files {
		rememberedFiles[i] = v.PutFile(f)
	}
	r.Files = rememberedFiles
	v.GitRepoSources = append(v.GitRepoSources, r)
	id := len(v.GitRepoSources) - 1
	v.GitRepoSources[id].SetCacheID(uint64(id))
	return v.GitRepoSources[id]
}

func (v *fingerprintInMemoryCache) FindGitSourceByURN(urn string) *record.GitRepoSource {
	v.reposLock.Lock()
	defer v.reposLock.Unlock()

	for id := range v.GitRepoSources {
		if v.GitRepoSources[id].URN() == urn {
			return v.GitRepoSources[id]
		}
	}
	return nil
}

func (v *fingerprintInMemoryCache) FindGitSourcesContainingFingerprint(fp *record.Fingerprint) []*record.GitRepoSource {

	if !fp.IsCached() {
		fp = v.GetFingerprintByGitSHA(fp.GitSHA.Raw())
		if fp == nil {
			return nil
		}
	}

	v.reposLock.Lock()
	defer v.reposLock.Unlock()

	repos := []*record.GitRepoSource{}
	for _, r := range v.GitRepoSources {
		for _, f := range r.Files {
			if f.Fingerprint == fp {
				repos = append(repos, r)
			}
		}
	}
	return repos
}

func (v *fingerprintInMemoryCache) RememberedGitSourcesCount() int {
	v.reposLock.Lock()
	defer v.reposLock.Unlock()
	return len(v.GitRepoSources)
}

func (v *fingerprintInMemoryCache) PutArchiveFile(r *record.ArchiveFile) *record.ArchiveFile {
	v.archivesLock.Lock()
	defer v.archivesLock.Unlock()

	r.File = v.PutFile(r.File)

	for i := range v.ArchiveFiles {
		if v.ArchiveFiles[i].File == r.File {
			// log.Println("archive already known")
			return v.ArchiveFiles[i]
		}
	}

	// log.Println("New archive? How can it be!")
	rememberedFiles := make([]*record.File, len(r.Entries))
	for i, f := range r.Entries {
		rememberedFiles[i] = v.PutFile(f)
	}
	r.Entries = rememberedFiles
	v.ArchiveFiles = append(v.ArchiveFiles, r)
	id := len(v.ArchiveFiles) - 1
	v.ArchiveFiles[id].SetCacheID(uint64(id))
	// log.Printf("Remembered archive: %+v\n", r.File)
	return v.ArchiveFiles[id]
}

func (v *fingerprintInMemoryCache) GetArchiveFile(f *record.File) *record.ArchiveFile {
	v.archivesLock.Lock()
	defer v.archivesLock.Unlock()

	if !f.IsCached() {
		f = v.GetFileByNameAndGitSHA(f.Path, f.Fingerprint.GitSHA.Raw())
		if f == nil {
			// log.Println("No existing file for archive")
			return nil
		}
	}

	for id := range v.ArchiveFiles {
		// log.Printf("%s:%s ?= %s:%s...   ", f.Path, f.Fingerprint.GitSHA.String(), v.archiveFiles[id].File.Path, v.archiveFiles[id].File.Fingerprint.GitSHA.String())
		if v.ArchiveFiles[id].File == f {
			// log.Println("FOUND!")
			return v.ArchiveFiles[id]
		}
		// log.Println("Nope :-(")
	}
	return nil
}

// FindArchiveFilesContainingFingerprint finds all archives that directly contain a file with the given fingerprint
func (v *fingerprintInMemoryCache) FindArchiveFilesContainingFingerprint(fp *record.Fingerprint) []*record.ArchiveFile {
	// Direct containment
	files := v.FindFilesWithFingerprint(fp)
	directArchives := []*record.ArchiveFile{}
	for _, file := range files {
		for _, a := range v.ArchiveFiles {
			for _, entry := range a.Entries {
				if entry == file {
					directArchives = append(directArchives, a)
				}
			}
		}
	}

	// indirectArchives := []*binprint.ArchiveFile{}
	// for _, da := range directArchives {
	// 	for _, a := range v.ArchiveFiles {
	// 		if a == da {
	// 			continue
	// 		}
	// 		for _, entry := range a.Entries {
	// 			if entry == da.File {
	// 				indirectArchives = append(indirectArchives, a)
	// 			}
	// 		}
	// 	}
	// }

	return directArchives
}
