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
			if result == nil {
				continue
			}
			fmt.Printf("%s  %s\n", result.Fingerprint.String(), path)
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

func init() {
	rootCmd.AddCommand(hashCmd)
	hashCmd.AddCommand(hashAllCmd)
	hashCmd.AddCommand(makeHashCommand("md5"))
	hashCmd.AddCommand(makeHashCommand("sha1"))
	hashCmd.AddCommand(makeHashCommand("sha256"))
	hashCmd.AddCommand(makeHashCommand("sha384"))
	hashCmd.AddCommand(makeHashCommand("sha512"))
	hashCmd.AddCommand(makeHashCommand("git"))
	hashCmd.AddCommand(makeHashCommand("hwy64"))
	hashCmd.AddCommand(makeHashCommand("hwy128"))
	hashCmd.AddCommand(makeHashCommand("hwy256"))
}
