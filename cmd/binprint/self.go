// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/IBM/binprint/record"
)

// selfCmd represents the id command
var selfCmd = &cobra.Command{
	Use:   "self",
	Short: "Print hashes for the binprint executable",
	Run: func(cmd *cobra.Command, args []string) {
		fp, err := record.Self()
		if err != nil {
			panic(err)
		}
		// Standard/portable hashes
		fmt.Printf("md5:%s\n", fp.MD5)
		fmt.Printf("sha1:%s\n", fp.SHA1)
		fmt.Printf("sha256:%s\n", fp.SHA256)
		fmt.Printf("sha384:%s\n", fp.SHA384)
		fmt.Printf("sha512:%s\n", fp.SHA512)
		// Same output as git-hash-object would give
		fmt.Printf("gitsha:%s\n", fp.GitSHA)
		// Super fast hashes, but with binprint specific salt
		fmt.Printf("hwy64:%s\n", fp.Hwy64)
		fmt.Printf("hwy128:%s\n", fp.Hwy128)
		fmt.Printf("hwy256:%s\n", fp.Hwy256)
	},
}

func init() {
	rootCmd.AddCommand(selfCmd)
}
