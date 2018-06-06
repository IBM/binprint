// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package store

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/golang/snappy"
	"github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
	"github.com/steakknife/bloomfilter"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"gopkg.in/yaml.v2"

	"github.com/IBM/binprint/hash"
	"github.com/IBM/binprint/record"
)

// specify whether to treat the gob serialization as the canonical form or not.
var useGob = false

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

// SerializedCache is an alternative representation of fingerprintInMemoryCache that uses
// numeric IDs in place of pointers. Other than creating the serialized struct from an existing
// fingerprintInMemoryCache, it is directly serializable using the defaults for more or less
// any encoding format desired
type SerializedCache struct {
	Fingerprints []record.SerializedFingerprint
	Files        []record.SerializedFile
	Archives     []record.SerializedArchiveFile
	Repos        []record.SerializedGitRepo
	StatCache    map[CachedStatFingerprintKey]uint64
}

// NewSerializedCache creates a new serializable copy of the current cache
func (v *fingerprintInMemoryCache) NewSerializedCache() *SerializedCache {
	v.fingerprintsLock.Lock()
	defer v.fingerprintsLock.Unlock()
	v.filesLock.Lock()
	defer v.filesLock.Unlock()
	v.archivesLock.Lock()
	defer v.archivesLock.Unlock()
	v.reposLock.Lock()
	defer v.reposLock.Unlock()

	onDisk := SerializedCache{
		Fingerprints: make([]record.SerializedFingerprint, len(v.Fingerprints)),
		Files:        make([]record.SerializedFile, len(v.Files)),
		Archives:     make([]record.SerializedArchiveFile, len(v.ArchiveFiles)),
		Repos:        make([]record.SerializedGitRepo, len(v.GitRepoSources)),
		StatCache:    make(map[CachedStatFingerprintKey]uint64, v.statCache.Len()),
	}

	// 1. encode the fingerprints as-is, but as a map instead of a list since we're using the
	// slice index as a key already and so we want to make it more official
	for i, f := range v.Fingerprints {
		id := uint64(i)
		onDisk.Fingerprints[i] = record.SerializedFingerprint{
			Fingerprint: *f,
			ID:          id,
		}
		// onDisk.Fingerprints[uint64(i)] = f
	}

	// 2. encode the files, they reference fingerprints and need mapping
	for i, f := range v.Files {
		// log.Printf("Storing file %s (%d) as %d\n", f.Path, f.CacheID(), i)
		onDisk.Files[i] = record.SerializedFile{
			ID:          f.CacheID(),
			Path:        f.Path,
			Fingerprint: f.Fingerprint.CacheID(),
		}
	}

	// 3. encode the archives, they join files to other files
	for i, a := range v.ArchiveFiles {
		id := uint64(i)
		archive := record.SerializedArchiveFile{
			ID:   id,
			File: a.File.CacheID(),
		}
		archive.Entries = make([]uint64, len(a.Entries))
		for ii, ep := range a.Entries {
			archive.Entries[ii] = ep.CacheID()
		}
		onDisk.Archives[i] = archive
		// memoryCachedArchiveFile{
		// 	FileID:   a.File.CacheID(),
		// 	EntryIDs: entryIDs,
		// }
	}

	// 4. encode the repos, they reference files and need mapping
	for i, r := range v.GitRepoSources {
		repo := record.SerializedGitRepo{Branch: r.Branch, Commit: r.Commit, Tag: r.Tag, URL: r.URL}
		repo.Files = make([]uint64, len(r.Files))
		for ii, fp := range r.Files {
			repo.Files[ii] = fp.CacheID()
		}
		onDisk.Repos[i] = repo
		// memoryCachedGitSource{
		// 	GitRepoSource: *r,
		// 	FileIDs:       fileIds,
		// }
		// onDisk.Repos[i].GitRepoSource.Files = nil
	}

	// 5. encode the stat cache
	statKeys := v.statCache.Keys()
	for _, k := range statKeys {
		sk := k.(CachedStatFingerprintKey)
		fp, ok := v.statCache.Peek(k)
		if !ok {
			log.Println("cache miss on known stat key")
			continue
		}
		f := fp.(*record.Fingerprint)
		onDisk.StatCache[sk] = f.CacheID()
	}

	return &onDisk
}

func (v *fingerprintInMemoryCache) loadSerializedCache(onDisk *SerializedCache) error {
	v.fingerprintsLock.Lock()
	defer v.fingerprintsLock.Unlock()
	v.filesLock.Lock()
	defer v.filesLock.Unlock()
	v.archivesLock.Lock()
	defer v.archivesLock.Unlock()
	v.reposLock.Lock()
	defer v.reposLock.Unlock()

	// 1. decode the fingerprints, they were directly encoded, but as a map instead of list
	fpCount := len(onDisk.Fingerprints)
	v.gitSHAIndex = make(map[hash.GitShaDigest]uint64, fpCount)
	// v.gitSHAIndex2 = NewGitShaIndexArr()
	v.Fingerprints = make([]*record.Fingerprint, fpCount)
	for i, sf := range onDisk.Fingerprints {
		id := uint64(i)
		if id != sf.ID {
			return errors.New("Mismatched fingerprint id")
		}
		fingerprint := sf.Fingerprint
		fingerprint.SetCacheID(id)
		v.Fingerprints[i] = &fingerprint
		v.gitSHAIndex[fingerprint.GitSHA] = id
		v.gitSHAFilter.Add(fingerprint.GitSHA)
	}

	// 2. decode the files, which are serialized using a different type
	fileCount := len(onDisk.Files)
	v.Files = make([]*record.File, fileCount)
	for i, sf := range onDisk.Files {
		id := uint64(i)
		if id != sf.ID {
			return errors.New("Mismatched file id")
		}
		// v.Files[i] = &onDisk.Files[i].File
		v.Files[id] = &record.File{Fingerprint: v.Fingerprints[sf.Fingerprint], Path: sf.Path}
		// v.Files[i].Fingerprint = v.Fingerprints[f.FingerprintID]
		v.Files[id].SetCacheID(id)
	}

	// 3. encode the archives, they join files to other files
	archiveCount := len(onDisk.Archives)
	v.ArchiveFiles = make([]*record.ArchiveFile, archiveCount)
	for i, sa := range onDisk.Archives {
		id := uint64(i)
		if id != sa.ID {
			return errors.New("Mismatched archive id")
		}
		entries := make([]*record.File, len(sa.Entries))
		for ii, eID := range sa.Entries {
			entries[ii] = v.Files[eID]
		}
		archive := record.ArchiveFile{
			File:    v.Files[sa.File],
			Entries: entries,
		}
		archive.SetCacheID(id)
		v.ArchiveFiles[id] = &archive
		// v.ArchiveFiles[i].SetCacheID(uint64(i))
	}

	// 4. decode the repos
	repoCount := len(onDisk.Repos)
	v.GitRepoSources = make([]*record.GitRepoSource, repoCount)
	for i, r := range onDisk.Repos {
		entries := make([]*record.File, len(r.Files))
		for ii, fid := range r.Files {
			entries[ii] = v.Files[fid]
		}
		v.GitRepoSources[i] = &record.GitRepoSource{
			Branch: r.Branch,
			Commit: r.Commit,
			Tag:    r.Tag,
			URL:    r.URL,
			Files:  entries,
		}
		// } onDisk.Repos[i].GitRepoSource
		// v.GitRepoSources[i].Files = make([]*binprint.File, len(r.FileIDs))

		v.GitRepoSources[i].SetCacheID(uint64(i))
	}

	// 5. decode the stat cache
	for statKey, fpID := range onDisk.StatCache {
		v.statCache.Add(statKey, v.Fingerprints[fpID])
	}

	return nil
}

// newCachedStatFingerprintKey takes an os.FileInfo to create a unique key based
// on the inode, size, and mtime of the target file
func (v *fingerprintInMemoryCache) newCachedStatFingerprintKey(fileInfo os.FileInfo) CachedStatFingerprintKey {
	stat := fileInfo.Sys().(*syscall.Stat_t)
	str := strconv.FormatInt(stat.Size, 36) + "," + strconv.FormatUint(stat.Ino, 36) + "," + strconv.FormatInt(fileInfo.ModTime().UnixNano(), 36)
	return CachedStatFingerprintKey(str)
}

func (v *fingerprintInMemoryCache) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	encoder := gob.NewEncoder(&b)

	onDisk := v.NewSerializedCache()
	if err := encoder.Encode(onDisk); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (v *fingerprintInMemoryCache) MarshalYAML() (interface{}, error) {
	return v.NewSerializedCache(), nil
}

// UnmarshalBinary modifies the receiver so it must take a pointer receiver.
func (v *fingerprintInMemoryCache) UnmarshalYAML(unmarshal func(interface{}) error) error {
	onDisk := new(SerializedCache)

	if err := unmarshal(onDisk); err != nil {
		return err
	}

	return v.loadSerializedCache(onDisk)
}

// UnmarshalBinary modifies the receiver so it must take a pointer receiver.
func (v *fingerprintInMemoryCache) UnmarshalBinary(data []byte) error {
	onDisk := new(SerializedCache)

	b := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(b)
	if err := decoder.Decode(onDisk); err != nil {
		return err
	}

	return v.loadSerializedCache(onDisk)
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

// PersistRememberedObjects takes the accumulated in-memory scan result database and serializes it to one or more files on disk.
func (v *fingerprintInMemoryCache) PersistRememberedObjects() {
	if err := v.Verify(); err != nil {
		log.Println("In-memory cache is inconsistent, not persisting.", err)
		return
	}

	onDisk := v.NewSerializedCache()

	binFile, err := os.Create("fingerprint.gob")
	if err != nil {
		log.Println("Error persisting in-memory cache:", err)
		return
	}
	snappyFile := snappy.NewBufferedWriter(binFile)
	gobEncoder := gob.NewEncoder(snappyFile)
	if err := gobEncoder.Encode(onDisk); err != nil {
		log.Println("Error persisting in-memory cache:", err)
	}
	if err := snappyFile.Flush(); err != nil {
		log.WithError(err).Print("Failed to flush serialized cache")
	}
	if err := snappyFile.Close(); err != nil {
		log.WithError(err).Print("Failed to close snappy stream")
	}
	if err := binFile.Close(); err != nil {
		log.WithError(err).Print("Failed to close gob file")
	}

	yamlFile, err := os.Create("fingerprint.yaml")
	if err != nil {
		log.Println("Error persisting in-memory cache:", err)
		return
	}
	ymlEncoder := yaml.NewEncoder(yamlFile)
	if err := ymlEncoder.Encode(onDisk); err != nil {
		log.WithError(err).Print("Error encoding cache to yaml")
		log.Println("Error persisting in-memory cache:", err)
	}
	if err := ymlEncoder.Close(); err != nil {
		log.WithError(err).Print("Error flushing yaml encoder")
	}
	if err := yamlFile.Close(); err != nil {
		log.WithError(err).Print("Error closing yaml file")
	}
}

// RestoreRememberedObjects loads a persisted database from disk
func RestoreRememberedObjects() record.Store {
	onDisk := new(SerializedCache)
	if useGob {
		indexFile, err := os.Open("fingerprint.gob")
		if err != nil {
			log.Println("Error restoring in-memory cache:", err)
			return nil
		}
		defer indexFile.Close()
		index := snappy.NewReader(indexFile)
		// index, err := gzip.NewReader(indexFile)
		if err != nil {
			log.Println("Error restoring in-memory cache:", err)
			return nil
		}
		indexDecoder := gob.NewDecoder(index)
		if err := indexDecoder.Decode(onDisk); err != nil {
			log.Println("Error restoring in-memory cache:", err)
			// resetCache()
			return nil
		}
	} else {
		indexFile, err := os.Open("fingerprint.yaml")
		if err != nil {
			log.Println("Error restoring in-memory cache:", err)
			return nil
		}
		defer indexFile.Close()
		indexDecoder := yaml.NewDecoder(indexFile)
		if err := indexDecoder.Decode(onDisk); err != nil {
			log.Println("Error restoring in-memory cache:", err)
			// resetCache()
			return nil
		}
	}

	cache := newInMemoryCache()
	cache.loadSerializedCache(onDisk)

	if err := cache.Verify(); err != nil {
		log.Println("Restore failed due to inconsistency:", err)
		// resetCache()
		return nil
	}
	return cache
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

var logger = logrus.New()
var log logrus.FieldLogger

func init() {
	log = logger.WithField("prefix", "cache")
	logger.Formatter = new(prefixed.TextFormatter)
	logger.Level = logrus.DebugLevel
}
