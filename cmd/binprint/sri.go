// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/IBM/binprint/scanner"
)

// sriCmd represents the id command
var sriCmd = &cobra.Command{
	Use:   "sri <PATH...>",
	Short: "Print Subresource Integrity strings",
	Long:  `Each named input is scanned and a multi-hash SRI string is printed.`,
	Run: func(cmd *cobra.Command, args []string) {
		for _, file := range args {
			id := scanner.IdentifyFile(file)
			if id != nil {
				fmt.Printf("%s: %s\n", file, id.SRI())
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(sriCmd)
}
