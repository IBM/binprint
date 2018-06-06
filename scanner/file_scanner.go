// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"io"
	"os"

	pb "gopkg.in/cheggaaa/pb.v1"

	"github.com/IBM/binprint/record"
)

// IsScannablePath returns true if the name matches an existing path that looks like something we can scan.
func IsScannablePath(name string, stat os.FileInfo) bool {
	var err error
	if stat == nil {
		stat, err = os.Stat(name)
	}
	return err == nil && (stat.IsDir() || stat.Mode().IsRegular())
}

// var myFingerprint *binprint.Fingerprint

// func init() {
// 	fileName, err := os.Executable()
// 	if err != nil {
// 		return
// 	}
// 	// IdentifyFile scans the specified file and returns a binprint.File record of it. The result may be cached, based on the inode, mtime, and size of the file.
// 	stat, err := os.Stat(fileName)
// 	if err != nil {
// 		panic(err)
// 	}
// 	myFingerprint = new(binprint.Fingerprint)
// 	f, err := os.Open(fileName)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer f.Close()
// 	calcMissingSums(myFingerprint, f, stat.Size())
// }

// IdentifyFileWithStat returns digest results for the provided file, either from
// cache or by scanning the file
func IdentifyFileWithStat(fileName string, stat os.FileInfo, bar *pb.ProgressBar) *record.File {
	cfp := cache.GetStatFingerprint(stat)
	if cfp != nil {
		// Cache hit!
		if bar != nil {
			bar.Add64(stat.Size())
		}

		return cache.PutFile(&record.File{
			Path:        fileName,
			Fingerprint: cache.PutFingerprint(cfp),
		})
	}

	var result record.Fingerprint
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var fReader io.Reader
	if bar != nil {
		fReader = bar.NewProxyReader(f)
	} else {
		fReader = f
	}
	result.CalculateSums(fReader, stat.Size())
	fp := cache.PutFingerprint(&result)

	cache.PutStatFingerprint(stat, fp)

	fileRes := cache.PutFile(&record.File{
		Path:        fileName,
		Fingerprint: fp,
	})

	return fileRes
}

// IdentifyFile scans the specified file and returns a binprint.File record of it. The result may be cached, based on the inode, mtime, and size of the file.
func IdentifyFile(fileName string) *record.File {
	stat, err := os.Stat(fileName)
	if err != nil {
		panic(err)
	}
	return IdentifyFileWithStat(fileName, stat, nil)
}
