// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package scanner

import (
	"time"
)

// logTime returns a function that will log the elapsed time since it LogTime was called.
// Example usage:
//   defer logTime("thing I am timing")()
func logTime(name string) func() {
	start := time.Now()
	return func() {
		log.Printf("%s: %s\n", name, time.Since(start).String())
	}
}
