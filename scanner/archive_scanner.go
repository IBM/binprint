// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/blakesmith/ar"
	cpio "github.com/cavaliercoder/go-cpio"

	"github.com/IBM/binprint/record"
)

// some archive formats require random access so we can't just
// make this API io.Reader based and pass in a passthrough stream
type archiveScanner func(string, os.FileInfo, io.Reader, <-chan *record.Fingerprint, int, int) (*record.File, *record.ArchiveFile)

var archiveScanners map[string]archiveScanner

func init() {
	archiveScanners = map[string]archiveScanner{
		".zip":     scanZip,
		".jar":     scanZip,
		".tar":     scanTar,
		".txz":     compressedTar("xz"),
		".tar.xz":  compressedTar("xz"),
		"tar.sz":   compressedTar("snappy"),
		"tar.lzma": compressedTar("lzma"),
		".tgz":     compressedTar("gzip"),
		".tar.gz":  compressedTar("gzip"),
		".tar.bz2": compressedTar("bz2"),
		".tbz2":    compressedTar("bz2"),
		".ar":      scanAR,
		".cpio":    scanCPIO,
		// TODO: consider implementing these?
		// tar.Z == compress (LZW)
		// tar.z == deflate
	}
}

func consumeRemainder(rdr io.Reader) error {
	remainder, err := ioutil.ReadAll(rdr)
	if err == io.EOF {
		err = nil
	}
	if err == nil {
		if len(remainder) != 0 && bytes.Count(remainder, []byte{0}) != len(remainder) {
			log.Print(rdr)
			log.Print(hex.Dump(remainder))
			err = errors.New("remainder of buffer was NOT 0 padding")
		}
	}
	return err
}

// IsScannableArchive checks whether the given file name looks like a supported archive format
func IsScannableArchive(name string) bool {
	for ext := range archiveScanners {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func getArchiveScanner(name string) archiveScanner {
	for ext, scanner := range archiveScanners {
		if strings.HasSuffix(name, ext) {
			return scanner
		}
	}
	return nil
}

func compressedTar(algorithm string) archiveScanner {
	return func(fileName string, stat os.FileInfo, body io.Reader, fpResult <-chan *record.Fingerprint, depth int, limit int) (*record.File, *record.ArchiveFile) {
		tarFileReader, err := Decompress(algorithm, body)
		if err != nil {
			log.WithError(err).Println("Error decompressing tar")
			return nil, nil
		}
		return scanTarStream(fileName, tarFileReader, fpResult, depth, limit)
	}
}

func scanTar(fileName string, stat os.FileInfo, body io.Reader, fpResult <-chan *record.Fingerprint, depth int, limit int) (*record.File, *record.ArchiveFile) {
	return scanTarStream(fileName, body, fpResult, depth, limit)
}

func scanAR(fileName string, stat os.FileInfo, body io.Reader, fpResult <-chan *record.Fingerprint, depth int, limit int) (*record.File, *record.ArchiveFile) {
	return scanARStream(fileName, body, fpResult, depth, limit)
}

func scanCPIO(fileName string, stat os.FileInfo, body io.Reader, fpResult <-chan *record.Fingerprint, depth int, limit int) (*record.File, *record.ArchiveFile) {
	return scanCPIOStream(fileName, body, fpResult, depth, limit)
}

func scanTarStream(fileName string, tarFile io.Reader, fpResult <-chan *record.Fingerprint, depth int, limit int) (*record.File, *record.ArchiveFile) {
	flog := log.WithField("file", fileName).WithField("prefix", "tar")

	archive := new(record.ArchiveFile)
	entries := make(chan *record.File)
	done := make(chan error)

	go func() {
		defer close(entries)
		defer close(done)
		// Open and iterate through the files in the archive.
		tr := tar.NewReader(tarFile)
		entriesCount := 0
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break // End of archive
			}
			if err == tar.ErrHeader {
				// the 'archive/tar' package goes in to a permanent error state once it hits an error
				// and there's no way to convince it to just skip the bad header, so we just
				// create a new tar.Reader that starts where the previous one left off.
				// We keep doing this until we either get EOF and exit cleanly or some other io error and
				// we exit with a less recoverable error
				tr = tar.NewReader(tarFile)
				continue
			}
			if err != nil {
				log.Println(err)
				done <- err
				return
			}
			if hdr.FileInfo().IsDir() {
				continue
			}
			// log.Printf("tar entry: %s (%d bytes)", hdr.Name, hdr.Size)
			// TODO: if we find a file called `package/package.json` while scanning a tgz then there's a good chance
			// that the tarball we're scanning is actually a node package from npm. Need to find a way of scheduling
			// a re-scan of it as a node package
			entry := fingerprintArchiveEntry(hdr.Name, hdr.Size, tr, depth, limit)
			if entry == nil {
				flog.Error("Error scanning entry")
			} else {
				entries <- entry
				entriesCount++
			}

		}
		done <- nil
	}()

readLoop:
	for {
		select {
		case err := <-done:
			if err != nil {
				flog.WithError(err).Println("Error scanning")
				for range entries {
				}
				return nil, nil
			}
			break readLoop
		case entry := <-entries:
			if entry != nil {
				archive.Entries = append(archive.Entries, entry)
			}
		}
	}

	if len(fpResult) == 0 {
		if err := consumeRemainder(tarFile); err != nil {
			flog.WithError(err).Print("Error consuming archive trailer")
		}
	}
	archive.File = cache.PutFile(&record.File{
		Path:        fileName,
		Fingerprint: <-fpResult,
	})
	archive = cache.PutArchiveFile(archive)
	return archive.File, archive
}

func scanCPIOStream(fileName string, cpioFile io.Reader, fpResult <-chan *record.Fingerprint, depth int, limit int) (*record.File, *record.ArchiveFile) {
	flog := log.WithField("file", fileName).WithField("prefix", "cpio")
	archive := new(record.ArchiveFile)
	entries := make(chan *record.File)
	done := make(chan error)

	go func() {
		defer close(entries)
		defer close(done)
		// Open and iterate through the files in the archive.
		cr := cpio.NewReader(cpioFile)
		entriesCount := 0
		for {
			hdr, err := cr.Next()
			if err == io.EOF {
				break // End of archive
			}
			if err == tar.ErrHeader {
				// the 'archive/tar' package goes in to a permanent error state once it hits an error
				// and there's no way to convince it to just skip the bad header, so we just
				// create a new tar.Reader that starts where the previous one left off.
				// We keep doing this until we either get EOF and exit cleanly or some other io error and
				// we exit with a less recoverable error
				cr = cpio.NewReader(cpioFile)
				continue
			}
			if err != nil {
				log.Println(err)
				done <- err
				return
			}
			if hdr.FileInfo().IsDir() {
				continue
			}
			// TODO: should we normalize paths by stripping the leading `./` if present
			// log.Printf("cpio entry: %s (%d bytes)", hdr.Name, hdr.Size)
			entry := fingerprintArchiveEntry(hdr.Name, hdr.Size, cr, depth, limit)
			if entry == nil {
				flog.Error("Error scanning entry")
			} else {
				entries <- entry
				entriesCount++
			}
			// log.Printf("archive entry: %s", entry)
			// entries <- entry
			// entriesCount++
		}
		done <- nil
	}()

readLoop:
	for {
		select {
		case err := <-done:
			if err != nil {
				log.Println("Error scanning archive: ", fileName, err)
				for range entries {
				}
				return nil, nil
			}
			break readLoop
		case entry := <-entries:
			if entry != nil {
				archive.Entries = append(archive.Entries, entry)
			}
		}
	}

	if len(fpResult) == 0 {
		if err := consumeRemainder(cpioFile); err != nil {
			flog.WithError(err).Print("Error consuming archive trailer")
		}
	}
	archive.File = cache.PutFile(&record.File{
		Path:        fileName,
		Fingerprint: <-fpResult,
	})
	archive = cache.PutArchiveFile(archive)
	return archive.File, archive
}

func scanZip(fileName string, stat os.FileInfo, body io.Reader, archiveFingerprint <-chan *record.Fingerprint, depth int, limit int) (*record.File, *record.ArchiveFile) {
	flog := log.WithField("file", fileName).WithField("prefix", "zip")
	archive := new(record.ArchiveFile)
	entries := make(chan *record.File)
	done := make(chan error)

	go func() {
		defer close(entries)
		defer close(done)
		// zip files require random access to read, so we can't use the passthrough method
		// instead we'll just fingerprint it in parallel
		zipBytes, err := ioutil.ReadAll(body)
		if err != nil {
			flog.WithError(err).Println("Could not load ZIP file")
			done <- err
			return
		}
		zipBuffer := bytes.NewReader(zipBytes)
		zipFile, err := zip.NewReader(zipBuffer, int64(zipBuffer.Len()))
		if err != nil {
			flog.WithError(err).Println("Could not read ZIP file")
			done <- err
			return
		}

		for _, entry := range zipFile.File {
			if entry.Mode().IsDir() {
				continue
			}
			entryReader, err := entry.Open()
			if err != nil {
				done <- err
				return
			}
			// log.Printf("zip entry: %s (%d bytes)", entry.Name, entry.UncompressedSize64)
			entry := fingerprintArchiveEntry(entry.Name, int64(entry.UncompressedSize64), entryReader, depth, limit)
			if entry == nil {
				flog.Error("Error scanning entry")
			} else {
				entries <- entry
				// entriesCount++
			}
			entryReader.Close()
		}
		done <- nil
	}()

readLoop:
	for {
		select {
		case err := <-done:
			if err != nil {
				flog.WithError(err).Println("Error scanning")
				for range entries {
				}
				return nil, nil
			}
			break readLoop
		case entry := <-entries:
			if entry != nil {
				archive.Entries = append(archive.Entries, entry)
			}
		}
	}

	afp, ok := <-archiveFingerprint
	if !ok {
		flog.Println("archive fingerprint was already read?")
		return nil, nil
	}
	archive.File = cache.PutFile(&record.File{
		Path:        fileName,
		Fingerprint: afp,
	})
	archive = cache.PutArchiveFile(archive)
	return archive.File, archive
}

func scanARStream(fileName string, arFile io.Reader, fpResult <-chan *record.Fingerprint, depth int, limit int) (*record.File, *record.ArchiveFile) {
	flog := log.WithField("file", fileName).WithField("prefix", "ar")
	archive := new(record.ArchiveFile)
	entries := make(chan *record.File)
	done := make(chan error)

	go func() {
		defer close(entries)
		defer close(done)
		arr := ar.NewReader(arFile)
		entriesCount := 0
		for {
			hdr, err := arr.Next()
			if err == io.EOF {
				break // End of archive
			}
			if err != nil {
				log.Println(err)
				done <- err
				return
			}
			// the name field is a 16 byte fixed width.
			// some ar archives use a trailing `/` to desginate the end of the filename
			// some right-justify the file name
			// for our purposes, we'll just remove all leading and trailing spaces and '/'s
			cleanName := strings.Trim(hdr.Name, "/ ")
			// flog.Printf("ar entry: %s (%d bytes)", cleanName, hdr.Size)
			entry := fingerprintArchiveEntry(cleanName, hdr.Size, arr, depth, limit)
			if entry == nil {
				flog.Error("Error scanning entry")
			} else {
				entries <- entry
				entriesCount++
			}
			// entriesCount++
		}
		done <- nil
	}()

readLoop:
	for {
		select {
		case err := <-done:
			if err != nil {
				flog.WithError(err).Println("Error scanning")
				for range entries {
				}
				return nil, nil
			}
			break readLoop
		case entry := <-entries:
			if entry != nil {
				archive.Entries = append(archive.Entries, entry)
			}
		}
	}

	if len(fpResult) == 0 {
		if err := consumeRemainder(arFile); err != nil {
			flog.WithError(err).Print("Error consuming archive trailer")
		}
	}
	archive.File = cache.PutFile(&record.File{
		Path:        fileName,
		Fingerprint: <-fpResult,
	})
	archive = cache.PutArchiveFile(archive)
	return archive.File, archive
}

func fingerprintArchiveEntry(name string, size int64, content io.Reader, depth int, limit int) *record.File {
	flog := log.WithField("file", name).WithField("prefix", "fingerprintArchiveEntry")
	depth++

	// it's recursion, baby!
	if IsScannableArchive(name) {
		// log.Printf("depth %d/%d (%s)", depth, limit, name)
		// log.Println("Scanning archive inside an archive: ", name)
		file, _ := IdentifyArchiveContents(name, size, nil, content, depth, limit)
		if file != nil {
			return file
		}
	} else if IsScannablePackage(name) {
		// log.Printf("depth %d/%d (%s)", depth, limit, name)
		// log.Println("Scanning archive inside an archive: ", name)
		file, _ := IdentifyPackageContents(name, size, nil, content, depth, limit)
		if file != nil {
			return file
		}
	} else {
		fp := new(record.Fingerprint)
		err := fp.CalculateSums(content, size)
		if err != nil {
			flog.WithError(err).Error("Could not calculate sums for archive entry")
			return nil
		}
		fp = cache.PutFingerprint(fp)
		return cache.PutFile(&record.File{
			Path:        name,
			Fingerprint: fp,
		})
	}
	return nil
}

// IdentifyArchiveContents recursively scans an archive to fingerprint everything it finds
func IdentifyArchiveContents(fileName string, size int64, stat os.FileInfo, archiveBody io.Reader, depth int, limit int) (*record.File, *record.ArchiveFile) {
	flog := log.WithField("file", fileName).WithField("prefix", "IdentifyArchiveContents")
	// if depth > 1 {
	// 	flog.Print("Getting deep..")
	// }

	if stat != nil {
		if size == 0 && stat.Size() != 0 {
			size = stat.Size()
		}
		if size != stat.Size() {
			flog.Fatal("2 different sizes given")
		}
		fp := cache.GetStatFingerprint(stat)
		// fp := LookupStatCachedFingerprint(stat)
		if fp != nil {
			files := cache.FindFilesWithFingerprint(fp)
			for _, f := range files {
				// log.Printf(".")
				existing := cache.GetArchiveFile(f)
				if existing != nil {
					return nil, existing
				}
			}
		}
	}

	var archive *record.ArchiveFile
	var file *record.File

	scanner := getArchiveScanner(fileName)
	if scanner != nil {
		if archiveBody == nil {
			archiveFileReader, err := os.Open(fileName)
			if err != nil {
				panic(err)
			}
			defer archiveFileReader.Close()
			archiveBody = archiveFileReader
		}
		if archiveBody == nil {
			flog.Fatal("how is this still nil?")
		}
		// check for nested passthroughs?
		// flog.Print("Starting scan")
		archiveReader, fpResult := fingerprintPassthrough(archiveBody, size, stat)
		file, archive = scanner(fileName, stat, archiveReader, fpResult, depth, limit)
		// flog.Print("Finished scan")
	}

	if archive != nil && stat != nil {
		cache.PutStatFingerprint(stat, file.Fingerprint)
	}
	return file, archive
}
