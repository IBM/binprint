// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"io"
	"os"
	"path/filepath"
	"sync"

	pb "gopkg.in/cheggaaa/pb.v1"
	git "gopkg.in/libgit2/git2go.v27"

	"github.com/IBM/binprint/record"
)

type pathEntry struct {
	Path string
	Stat os.FileInfo
}

type deepScanner func(string, int64, os.FileInfo, io.Reader, int, int) (*record.File, *record.ArchiveFile)

// ScanAndInventoryPath performs a recursive scan of all the files and
// directories rooted at the given path. Some paths are scanned using
// intelligent format-specific scanners. Git repos (.git folders) are scanned as
// a git repositories instead of as directories of files. Archive files of
// supported types (based on file extension only) are scanned both as a file as
// well as their contents being recursively scanned using the same rules. Nested
// archives and git repos are also scanned recursively.
func ScanAndInventoryPath(dir string) {
	paths := []pathEntry{}
	repos := []pathEntry{}
	archives := []pathEntry{}
	packages := []pathEntry{}
	// log.Println("Scanning...")
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("prevent panic by handling failure accessing a path %q: %v\n", dir, err)
			return nil
			// return err
		}
		if info.IsDir() && info.Name() == ".git" {
			repos = append(repos, pathEntry{path, info})
			return filepath.SkipDir
		}
		// walk uses os.Lstat, which will confuse the hasher when it ends up hashing a large file
		// instead of a tiny symlink
		if info.Mode()&os.ModeSymlink != 0 {
			info, err = os.Stat(path)
			if err != nil {
				log.WithField("file", path).Printf("Could not stat file")
				return nil
				// return err
			}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			log.WithField("file", path).Print("Could not resolve to non-symlink")
			return nil
		}

		// TODO: prune files that match what is in the git repo?
		if info.IsDir() {
			return nil
		} else if IsScannableArchive(path) {
			archives = append(archives, pathEntry{path, info})
		} else if IsScannablePackage(path) {
			packages = append(packages, pathEntry{path, info})
		} else {
			paths = append(paths, pathEntry{path, info})
		}

		return nil
	})
	if err != nil {
		log.WithError(err).Println("Error during search for scannable files")
		// panic(err)
	}

	log.Printf("Found: %d files, %d repos, %d archives, %d packages\n", len(paths), len(repos), len(archives), len(packages))
	if len(paths) > 0 {
		var totalBytes int64
		for _, p := range paths {
			totalBytes += p.Stat.Size()
		}
		var bar *pb.ProgressBar
		var byteProgress *pb.ProgressBar
		ratio := totalBytes / int64(len(paths))
		// log.Printf("files: %d, bytes: %d, ratio: %d\n", len(paths), totalBytes, ratio)
		if ratio > 10000 {
			// we've got a small number of larger files, so count bytes instead
			bar = pb.New64(totalBytes).SetUnits(pb.U_BYTES)
			byteProgress = bar
		} else {
			bar = pb.New(len(paths))
		}
		bar.Prefix("Files:").Start()
		for _, p := range paths {
			// res :=
			IdentifyFileWithStat(p.Path, p.Stat, byteProgress)
			if byteProgress == nil {
				bar.Increment()
			}
			// log.Printf("Scanning %s (%d bytes)\n", p.Path, p.Stat.Size())
			// res := IdentifyFileWithStat(p.Path, p.Stat, bar)
			// if res.GitSha1sum == hash.NullGitShaDigest {
			// 	log.Println("Missed git shasum: ", p.Path)
			// }
			// if !IsInRepo(res) {
			// 	log.Printf("Interesting file: %s\n", p.Path)
			// }
		}
		bar.Finish()
	}
	if len(repos) > 0 {
		repoSources := []record.GitRepoSource{}
		// bar := pb.New(len(repos)).Prefix("Repositories:").Start()
		repoRefs := []*git.Reference{}
		for _, r := range repos {
			repoRefs = append(repoRefs, InterestingGitRefs(r.Path)...)
			// bar.Increment()
		}
		// bar.Finish()
		// bar = pb.New(len(repoRefs)).Prefix("Repository refs:").Start()
		for _, ref := range repoRefs {
			// log.Printf("Repo ref %d/%d\n", i, len(repoRefs))
			src := GitRepoSourceFromRef(ref)
			if src != nil {
				repoSources = append(repoSources, *src)
			}
			// bar.Increment()
		}
		// bar.Finish()
	}
	if len(archives) > 0 {
		work := make(chan pathEntry, len(archives))
		results := make(chan *record.ArchiveFile, len(archives))
		wg := sync.WaitGroup{}
		for _, a := range archives {
			work <- a
		}
		close(work)
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go deepScanWorker(IdentifyArchiveContents, work, results, &wg)
		}
		go func() {
			bar := pb.New(len(archives)).Prefix("Archives:").Start()
			for range results {
				bar.Increment()
			}
			bar.Finish()
		}()
		wg.Wait()
		close(results)
	}
	if len(packages) > 0 {
		work := make(chan pathEntry, len(packages))
		results := make(chan *record.ArchiveFile, len(packages))
		wg := sync.WaitGroup{}
		for _, a := range packages {
			work <- a
		}
		close(work)
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go deepScanWorker(IdentifyPackageContents, work, results, &wg)
		}
		go func() {
			bar := pb.New(len(packages)).Prefix("Packages:").Start()
			for range results {
				bar.Increment()
			}
			bar.Finish()
		}()
		wg.Wait()
		close(results)
	}
}

func deepScanWorker(scan deepScanner, input <-chan pathEntry, output chan<- *record.ArchiveFile, wg *sync.WaitGroup) {
	for file := range input {
		// log.Printf("\nStart %s\n", file.Path)
		_, a := scan(file.Path, file.Stat.Size(), file.Stat, nil, 0, 10)
		output <- a
		// log.Printf("\nFinish %s\n", file.Path)
	}
	wg.Done()
}
