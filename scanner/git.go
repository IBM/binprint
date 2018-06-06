// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"bytes"
	"regexp"
	"strings"

	pb "gopkg.in/cheggaaa/pb.v1"
	git "gopkg.in/libgit2/git2go.v27"

	"github.com/IBM/binprint/hash"
	"github.com/IBM/binprint/record"
)

// internal flag for controlling whether to calculate _all_ supported hashes or only the gitsha
var onlyGitSHA = false

// InterestingGitRefs identifies the refs in a repo that look "interesting" and worthy of scanning.
func InterestingGitRefs(path string) []*git.Reference {
	reject := regexp.MustCompile("remotes/annex|git-annex|remotes/pull")
	r, err := git.OpenRepository(path)
	if err != nil {
		return nil
	}
	refIter, err := r.NewReferenceIterator()
	defer refIter.Free()
	refs := []*git.Reference{}
	for {
		ref, err := refIter.Next()
		if err != nil {
			break
		}

		// Explicit inclusions first..
		if ref.IsBranch() {
			if isHead, _ := ref.Branch().IsHead(); isHead {
				// always include the HEAD
				refs = append(refs, ref)
				continue
			}
		}

		// Exclusions..
		if reject.MatchString(ref.Name()) {
			continue
		}
		if ref.IsRemote() && !strings.HasPrefix(ref.Shorthand(), "origin") {
			continue
		}
		if !ref.IsTag() && ref.Shorthand() != "master" && ref.Shorthand() != "HEAD" {
			continue
		}

		// Default to include
		refs = append(refs, ref)
	}
	// for _, ref := range refs {
	// 	isBranch := ref.IsBranch()
	// 	isTag := ref.IsTag()
	// 	isRemote := ref.IsRemote()
	// 	isHead := false
	// 	if isBranch {
	// 		isHead, _ = ref.Branch().IsHead()
	// 	}
	// 	log.Debugf("ref: %s (branch: %t, tag: %t, remote: %t, head: %t)\n", ref.Name(), isBranch, isTag, isRemote, isHead)
	// }
	return refs
}

// GitRepoSourceFromRef scans the given git ref and returns a GitRepoSource
// containing files/fingerprints for all the files in that ref.
func GitRepoSourceFromRef(ref *git.Reference) *record.GitRepoSource {
	src := new(record.GitRepoSource)
	if ref.IsTag() {
		src.Tag = ref.Shorthand()
	} else {
		src.Branch = ref.Shorthand()
	}
	commit, err := ref.Peel(git.ObjectCommit)
	if err != nil {
		log.Printf("Could not peel ref %s down to a commit: %v\n", ref.Name(), err)
	}
	cid := *commit.Id()
	src.Commit = hash.GitShaDigestFromRaw(cid)
	existing := cache.FindGitSourceByURN(src.URN())
	if existing != nil {
		return existing
	}

	// cachedSrc := GetGitSourceFromCache(src.URN())
	// if cachedSrc != nil {
	// 	// log.Printf("Cached git source found: %s (%d files)\n", cachedSrc.URN(), len(cachedSrc.Files))
	// 	return cachedSrc
	// }

	treeObj, err := ref.Peel(git.ObjectTree)
	if err != nil {
		log.Printf("Could not peel ref %s down to a tree: %v\n", ref.Name(), err)
		return nil
	}
	tree, err := treeObj.AsTree()
	if err != nil {
		// if it is not a tree at this point then something has gone irrecoverably wrong!
		panic(err)
	}

	entryCount := CountTreeEntries(tree)
	src.Files = make([]*record.File, 0, entryCount)
	bar := pb.New(entryCount).Prefix("git: " + ref.Shorthand() + " files:").Start()
	files := FilesChannelFromTree(tree, entryCount)
	for file := range files {
		src.RecordBlob(file)
		bar.Increment()
	}
	bar.Finish()
	// log.Println("Caching git source...")
	// CacheGitSource(src)
	return cache.PutGitSource(src)

	// log.Printf("Cached git source: %s\n", key)
	// return src
}

func filesChannelFromTree2(t *git.Tree, size int) <-chan *record.File {
	// give a bit of a buffer so the tree walker doesn't need to wait
	// for us to start consuming files before it can do anything
	files := make(chan *record.File, size/2)
	go func() {
		r := t.Owner()
		t.Walk(func(name string, te *git.TreeEntry) int {
			// a tree entry can be either a blob or a tree and t.Walk is taking care
			// of walking the tree -> tree paths for us
			if te.Type != git.ObjectBlob {
				return 0
			}
			filePath := name + te.Name
			files <- FileFromBlob(r, filePath, te.Id)
			return 0
		})
		close(files)
	}()
	return files
}

// FilesChannelFromTree creates a channel of binprint.File objects representing
// each file/blob in the given tree.
func FilesChannelFromTree(tree *git.Tree, numberOfBlobsInTree int) <-chan *record.File {
	// give a bit of a buffer so the tree walker doesn't need to wait
	// for us to start consuming files before it can do anything
	files := make(chan *record.File, numberOfBlobsInTree)
	type blobDetails struct {
		name string
		// sha1 [20]byte
		oid *git.Oid
	}
	// filesList := make([]*blobArg, 0, size)
	blobArgs := make(chan *blobDetails, numberOfBlobsInTree)
	repo := tree.Owner()
	// quickly run through the entire tree and grab all the entry names and blob ids
	go func() {
		tree.Walk(func(name string, entry *git.TreeEntry) int {
			// a tree entry can be either a blob or a tree and t.Walk is taking
			// care of walking the tree -> tree paths for us, so we can just
			// ignore them entirely
			if entry.Type != git.ObjectBlob {
				return 0
			}
			filePath := name + entry.Name
			file := FileFromExistingBlob(repo, filePath, entry.Id)
			if file != nil {
				// Fast path: if we already have a fingerprint in our cache with
				// a git sha that matches the blob id, then we can just create a
				// file entry directly from that
				files <- file
			} else {
				// otherwise, we'll have to add this blob id to the queue and do
				// a full scan of it outside of the tree walking. We do this
				// separately because the tree walk itself has already locked an
				// OS thread and each time we look up one of these blobs it will
				// also lock that OS thread. Splitting these up helps us keep
				// our resource contention down a little.
				blobArgs <- &blobDetails{name: filePath, oid: entry.Id}
			}
			// filesList = append(filesList, &blobArg{filePath, te.Id})
			return 0
		})
		close(blobArgs)
	}()
	// asynchronously transform the path + blob id in to binprint.File objects
	go func() {
		for blob := range blobArgs {
			files <- FileFromBlob(repo, blob.name, blob.oid)
		}
		close(files)
	}()
	return files
}

// FileFromBlob creates a full binprint.File record from a given path and blob
// id. The blob id is used as the git sha and doesn't need to be calculated, but
// the rest of the digests are generated by reading the blob contents from the
// git repo and performing the normal hashing operations. If this blob was
// previously recorded in a binprint.Fingerprint via the FileFromExistingBlob
// method then this call will back-fill any of the missing digest information.
func FileFromBlob(r *git.Repository, name string, blobID *git.Oid) *record.File {
	fp := cache.GetFingerprintByGitSHA(*blobID)
	if fp == nil {
		fp = &record.Fingerprint{
			GitSHA: hash.GitShaDigestFromRaw(*blobID),
			// {
			// 	Raw: [20]byte(*blobID),
			// },
		}
	}
	file := &record.File{
		Path:        name,
		Fingerprint: fp,
	}
	blob, err := r.LookupBlob(blobID)
	if err != nil {
		// there's pretty much no way this should happen
		log.Printf("WTF? %s can't be found?", blobID.String())
		panic(err)
	}
	file.Fingerprint.Size = blob.Size()
	if !onlyGitSHA {
		buf := bytes.NewBuffer(blob.Contents())
		file.Fingerprint.CalculateSums(buf, file.Fingerprint.Size)
	}
	return cache.PutFile(file)
}

// FileFromExistingBlob is a variant of FileFromBlob that will create a
// binprint.File record from the given name and blob id (what we calculate as a
// git sha). If there is no existing fingerprint with that git sha then nil is
// returned. If the existing fingerprint is incomplete (missing some digests)
// then this method will NOT fill them in. This method is intended to be a
// fastpath for git repo scanning that reads only information available in git
// object indices.
func FileFromExistingBlob(r *git.Repository, name string, blobID *git.Oid) *record.File {
	existingFingerprint := cache.GetFingerprintByGitSHA(*blobID)
	if existingFingerprint == nil {
		return nil
	}
	existingFile := cache.GetFileByNameAndGitSHA(name, *blobID)
	if existingFile != nil {
		return existingFile
	}
	return cache.PutFile(&record.File{
		Path:        name,
		Fingerprint: existingFingerprint,
	})
}

// CountTreeEntries returns the number of blobs in the given tree, scanning
// recursively through sub-trees.
func CountTreeEntries(tree *git.Tree) int {
	entries := 0
	tree.Walk(func(_ string, te *git.TreeEntry) int {
		if te.Type == git.ObjectBlob {
			entries++
		}
		return 0
	})
	return entries
}
