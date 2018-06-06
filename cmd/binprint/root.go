// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "binprint",
	Short: "File scanner for recording relationships between build inputs and outputs",
	Long: `The binprint utility scans various files and objects and records identifying
information about them, including various hashes (md5, sha1, sha256, etc.).
Some types of objects can be scanned recursively, recording fingerprint data
for the containing object as well as each contained object. Recursive scanners
are implemented for most archive file types, DEB and RPM packages, and Docker
images.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		return err
	}
	return nil
	// fmt.Printf("Memory:\n\tFingerprints: %d\n\tFiles: %d\n\tRepos: %d\n", client.RememberedFingerprintsCount(), client.RememberedFilesCount(), client.RememberedGitSourcesCount())
}
