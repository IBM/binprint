// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cavaliercoder/go-rpm"

	"github.com/IBM/binprint/record"
)

// TODO: possibly useful
//  - https://github.com/paultag/go-debian
//    for scanning host for installed packages and all sorts of other debian/ubuntu related things

// Also looked at:
// https://github.com/sassoftware/go-rpmutils

// some package formats require random access so we can't just
// make this API io.Reader based and pass in a passthrough stream
type pkgScanner func(string, os.FileInfo, io.Reader, <-chan *record.Fingerprint, int, int) (*record.File, *record.ArchiveFile)

var pkgScanners map[string]pkgScanner

func init() {
	pkgScanners = map[string]pkgScanner{
		".rpm": scanRPM,
		".deb": scanDEB,
		// ".gem": scanGEM,
		// TODO: what should be done about node packages?
	}
}

// IsScannablePackage returns true if the given filename looks like a supported package format
func IsScannablePackage(name string) bool {
	for ext := range pkgScanners {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func getPackageScanner(name string) pkgScanner {
	for ext, scanner := range pkgScanners {
		if strings.HasSuffix(name, ext) {
			return scanner
		}
	}
	return nil
}

func scanDEB(fileName string, stat os.FileInfo, body io.Reader, fpResult <-chan *record.Fingerprint, depth int, limit int) (*record.File, *record.ArchiveFile) {
	// flog := log.WithField("file", fileName)
	// deb packages are ar archives containing things like metadata and payload in tarballs with predefined names
	// TODO: scan the sub-archives in the context of this deb package instead of as standalone tarballs
	return scanAR(fileName, stat, body, fpResult, depth, limit)
}

func scanRPM(fileName string, stat os.FileInfo, body io.Reader, fpResult <-chan *record.Fingerprint, depth int, limit int) (*record.File, *record.ArchiveFile) {
	// TODO: take better advantage of API and record other metadata: https://github.com/cavaliercoder/go-rpm
	flog := log.WithField("file", fileName)
	rpmBytes, err := ioutil.ReadAll(body)
	if err != nil {
		flog.WithError(err).Println("Could not scan RPM contents")
		return nil, nil
	}
	rpmBody := bytes.NewReader(rpmBytes)
	pkg, err := rpm.ReadPackageFile(rpmBody)
	if err != nil {
		flog.WithError(err).Print("Could not parse rpm package body")
		return nil, nil
	}
	// fmt.Printf("\npkg: %s, summary: %s\nformat: %s, compression: %s\n", pkg.String(), pkg.Summary(), pkg.PayloadFormat(), pkg.PayloadCompression())
	payload, err := Decompress(pkg.PayloadCompression(), rpmBody)
	if err != nil {
		flog.WithError(err).Print("Could not decompress package contents")
		return nil, nil
	}
	return scanCPIOStream(fileName, payload, fpResult, depth, limit)
}

// IdentifyPackageContents recursively scans an package to fingerprint everything it finds
func IdentifyPackageContents(fileName string, size int64, stat os.FileInfo, pkgBody io.Reader, depth int, limit int) (*record.File, *record.ArchiveFile) {
	flog := log.WithField("file", fileName).WithField("prefix", "IdentifyPackageContents")
	// if depth > 1 {
	// 	flog.Print("Getting deep..")
	// }

	if stat != nil {
		if size == 0 && stat.Size() != 0 {
			size = stat.Size()
		}
		if size != stat.Size() {
			flog.Panic("2 different sizes given")
		}
		fp := cache.GetStatFingerprint(stat)
		if fp != nil {
			files := cache.FindFilesWithFingerprint(fp)
			for _, f := range files {
				// log.Printf(".")
				existing := cache.GetArchiveFile(f)
				if existing != nil {
					return existing.File, existing
				}
			}
		}
	}

	var pkg *record.ArchiveFile
	var file *record.File

	scanner := getPackageScanner(fileName)
	if scanner != nil {
		if pkgBody == nil {
			pkgFileReader, err := os.Open(fileName)
			if err != nil {
				panic(err)
			}
			defer pkgFileReader.Close()
			pkgBody = pkgFileReader
		}
		if pkgBody == nil {
			flog.Panic("how is this still nil?")
		}
		// check for nested passthroughs?
		// flog.Print("Starting scan")
		pkgReader, fpResult := fingerprintPassthrough(pkgBody, size, stat)
		file, pkg = scanner(fileName, stat, pkgReader, fpResult, depth, limit)
		// flog.Print("Finished scan")
	}

	if pkg != nil && stat != nil {
		cache.PutStatFingerprint(stat, file.Fingerprint)
	}
	return file, pkg
}
