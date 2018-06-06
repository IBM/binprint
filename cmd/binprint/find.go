// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/IBM/binprint/record"
	"github.com/IBM/binprint/scanner"
)

// findCmd represents the find command
var findCmd = &cobra.Command{
	Use: "find [flags] <PATTERN>",
	DisableFlagsInUseLine: true,
	Args:  cobra.MaximumNArgs(1),
	Short: "Find files/objects matching fingerprint",
	Run: func(cmd *cobra.Command, args []string) {
		scanner.RestoreRememberedObjects()
		for _, arg := range args {
			var fingerprint *record.Fingerprint
			if matcher, err := scanner.NewFingerprintMatcher(arg); err == nil {
				fmt.Printf("Parsed as digest: %s\n", matcher)
				fingerprint = scanner.FindMatchingFingerprint(matcher)
			} else {
				result := scanner.IdentifyFile(arg)
				if result == nil {
					continue
				}
				fingerprint = result.Fingerprint
			}
			if fingerprint == nil {
				continue
			}

			if repos := scanner.FindRepos(fingerprint); len(repos) > 0 {
				fmt.Println("Git Repositories:")
				for _, match := range repos {
					fmt.Printf(" - %s: %s\n", match.URN(), match.Find(fingerprint))
				}
			}

			if files := scanner.FindFiles(fingerprint); len(files) > 0 {
				fmt.Println("File matches:")
				for _, f := range files {
					fmt.Printf(" - %s\n", f.Path)
				}
			}

			// TODO: support deep searching instead of only archives that
			// directly contain the target
			if archives := scanner.FindArchives(fingerprint); len(archives) > 0 {
				fmt.Println("Archives containing matches:")
				for _, a := range archives {
					fmt.Printf(" - %s\n", a.File.Path)
				}
			}

			// TODO: support searching for packages containing target
		}
	},
}

func init() {
	rootCmd.AddCommand(findCmd)
}
