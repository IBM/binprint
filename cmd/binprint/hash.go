// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/IBM/binprint/hash"
	"github.com/IBM/binprint/scanner"
)

// hashCmd represents the hash command
var hashCmd = &cobra.Command{
	Use:   "hash <HASH> <FILE...>",
	Short: "Calculate hashes",
	Long:  `Each named input is scanned and multiple hashes are printed out.`,
}

var hashAllCmd = &cobra.Command{
	Use:   "all <PATH...>",
	Short: "Calculate all known hashes in parallel",
	Run: func(cmd *cobra.Command, args []string) {
		for _, path := range args {
			result := scanner.IdentifyFile(path)
			if result == nil || result.Fingerprint == nil {
				continue
			}
			for _, alg := range knownAlgorithms {
				fmt.Printf("%s:%s  %s\n", alg, result.Fingerprint.GetDigest(alg), path)
			}
		}
	},
}

func makeHashCommand(algorithm string) *cobra.Command {
	return &cobra.Command{
		Use: fmt.Sprintf("%s <PATH...>", algorithm),
		Run: func(cmd *cobra.Command, args []string) {
			for _, path := range args {
				result := mustHash(algorithm, path)
				fmt.Printf("%s  %s\n", result.String(), path)
			}
		},
	}
}

func mustStatAndOpen(path string) (os.FileInfo, *os.File) {
	stat, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to stat file: %s: %s", path, err)
		os.Exit(1)
	}
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open file: %s: %s", path, err)
		os.Exit(1)
	}
	return stat, file
}

func mustCopy(path string, dst io.WriteCloser, src io.Reader) {
	defer dst.Close()
	_, err := io.Copy(dst, src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read file: %s: %s", path, err)
		os.Exit(1)
	}
}

func mustHash(algorithm string, path string) hash.Digest {
	stat, file := mustStatAndOpen(path)
	hasher, err := hash.NewAsyncHash(algorithm, stat.Size())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	mustCopy(path, hasher, file)
	return hasher.Digest()
}

var knownAlgorithms = [...]string{
	"md5",
	"sha1",
	"sha256",
	"sha384",
	"sha512",
	"git",
	"hwy64",
	"hwy128",
	"hwy256",
}

func init() {
	rootCmd.AddCommand(hashCmd)
	hashCmd.AddCommand(hashAllCmd)
	for _, alg := range knownAlgorithms {
		hashCmd.AddCommand(makeHashCommand(alg))
	}
}
