// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/IBM/binprint/scanner"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use: "scan [flags] <PATH|IMAGE>...",
	DisableFlagsInUseLine: true,
	Args:  cobra.MinimumNArgs(1),
	Short: "Scans the named objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		scanner.RestoreRememberedObjects()
		defer scanner.PersistRememberedObjects()

		paths := []string{}
		images := []string{}

		for _, arg := range args {
			isPath := scanner.IsScannablePath(arg, nil)
			isImage := scanner.IsScannableImage(arg)
			if isPath {
				paths = append(paths, arg)
			}
			if isImage {
				images = append(images, arg)
			}
			if !isImage && !isPath {
				fmt.Printf("Cannot find scannable target: %s\n", arg)
			}
		}
		if len(images) > 0 {
			scanner.ScanDockerImages(images)
		}
		for _, path := range paths {
			scanner.ScanAndInventoryPath(path)
		}
		if len(images) == 0 && len(paths) == 0 {
			// this error isn't related to usage, it's more likely a typo
			cmd.SilenceUsage = true
			return errors.New("No scannable targets found")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
