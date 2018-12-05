// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package store

import (
	"bytes"
	"encoding/gob"
	"os"

	"github.com/golang/snappy"
	"gopkg.in/yaml.v2"

	"github.com/IBM/binprint/hash"
	"github.com/IBM/binprint/record"
)

// specify whether to treat the gob serialization as the canonical form or not.
var useGob = false

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
		Fingerprints: make([]record.SerializedFingerprint, 0, len(v.Fingerprints)),
		Files:        make([]record.SerializedFile, 0, len(v.Files)),
		Archives:     make([]record.SerializedArchiveFile, 0, len(v.ArchiveFiles)),
		Repos:        make([]record.SerializedGitRepo, 0, len(v.GitRepoSources)),
		StatCache:    make(map[CachedStatFingerprintKey]uint64, v.statCache.Len()),
	}

	// 1. encode the fingerprints as-is, but as a map instead of a list since we're using the
	// slice index as a key already and so we want to make it more official
	for _, f := range v.Fingerprints {
		onDisk.Fingerprints = append(onDisk.Fingerprints, record.SerializedFingerprint{
			Fingerprint: *f,
			ID:          f.CacheID(),
		})
	}

	// 2. encode the files, they reference fingerprints and need mapping
	for _, f := range v.Files {
		// log.Printf("Storing file %s (%d) as %d\n", f.Path, f.CacheID(), i)
		onDisk.Files = append(onDisk.Files, record.SerializedFile{
			ID:          f.CacheID(),
			Path:        f.Path,
			Fingerprint: f.Fingerprint.CacheID(),
		})
	}

	// 3. encode the archives, they join files to other files
	for _, a := range v.ArchiveFiles {
		archive := record.SerializedArchiveFile{
			ID:   a.CacheID(),
			File: a.File.CacheID(),
		}
		archive.Entries = make([]uint64, len(a.Entries))
		for ii, ep := range a.Entries {
			archive.Entries[ii] = ep.CacheID()
		}
		onDisk.Archives = append(onDisk.Archives, archive)
	}

	// 4. encode the repos, they reference files and need mapping
	for _, r := range v.GitRepoSources {
		repo := record.SerializedGitRepo{ID: r.CacheID(), Branch: r.Branch, Commit: r.Commit, Tag: r.Tag, URL: r.URL}
		repo.Files = make([]uint64, len(r.Files))
		for ii, fp := range r.Files {
			repo.Files[ii] = fp.CacheID()
		}
		onDisk.Repos = append(onDisk.Repos, repo)
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
	v.Fingerprints = make(map[uint64]*record.Fingerprint, fpCount)
	for _, sf := range onDisk.Fingerprints {
		id := sf.ID
		fp := new(record.Fingerprint)
		*fp = sf.Fingerprint
		fp.SetCacheID(id)
		if id >= v.FingerprintsNextKey {
			v.FingerprintsNextKey = id + 1
		}
		v.Fingerprints[id] = fp
		v.gitSHAIndex[fp.GitSHA] = id
		v.gitSHAFilter.Add(fp.GitSHA)
	}

	// 2. decode the files, which are serialized using a different type
	fileCount := len(onDisk.Files)
	v.Files = make(map[uint64]*record.File, fileCount)
	for _, sf := range onDisk.Files {
		id := sf.ID
		f := &record.File{Fingerprint: v.Fingerprints[sf.Fingerprint], Path: sf.Path}
		f.SetCacheID(id)
		if id >= v.FilesNextKey {
			v.FilesNextKey = id + 1
		}
		v.Files[id] = f
	}

	// 3. encode the archives, they join files to other files
	archiveCount := len(onDisk.Archives)
	v.ArchiveFiles = make(map[uint64]*record.ArchiveFile, archiveCount)
	for _, sa := range onDisk.Archives {
		id := sa.ID
		entries := make([]*record.File, len(sa.Entries))
		for ii, eID := range sa.Entries {
			entries[ii] = v.Files[eID]
		}
		archive := record.ArchiveFile{
			File:    v.Files[sa.File],
			Entries: entries,
		}
		archive.SetCacheID(id)
		if id >= v.ArchiveFilesNextKey {
			v.ArchiveFilesNextKey = id + 1
		}
		v.ArchiveFiles[id] = &archive
	}

	// 4. decode the repos
	repoCount := len(onDisk.Repos)
	v.GitRepoSources = make(map[uint64]*record.GitRepoSource, repoCount)
	for _, r := range onDisk.Repos {
		id := r.ID
		entries := make([]*record.File, len(r.Files))
		for ii, fid := range r.Files {
			entries[ii] = v.Files[fid]
		}
		gr := &record.GitRepoSource{
			Branch: r.Branch,
			Commit: r.Commit,
			Tag:    r.Tag,
			URL:    r.URL,
			Files:  entries,
		}
		gr.SetCacheID(id)
		if id >= v.GitRepoSourcesNextKey {
			v.GitRepoSourcesNextKey = id + 1
		}
		v.GitRepoSources[id] = gr
	}

	// 5. decode the stat cache
	for statKey, fpID := range onDisk.StatCache {
		v.statCache.Add(statKey, v.Fingerprints[fpID])
	}

	return nil
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
