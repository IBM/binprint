// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package main

import (
	_ "expvar"
	"net/http"
	_ "net/http/pprof"
	"os"

	"runtime"

	"github.com/pkg/profile"
	"github.com/sirupsen/logrus"
)

func realMain() error {
	// The libgit2 library is a wrapper around the C bindings and makes heavy
	// use of runtime.LockOSThread() (eg. in almost every call). To mitigate the
	// impact this has on our own concurrency, we want to make sure that we
	// allow enough OS threads to account for some of them being blocked some of
	// the time. This will probably become unnecessary once the go routine
	// scheduler improves at which point these calls will become no-ops anyway.
	current := runtime.GOMAXPROCS(0)
	if current < 2*runtime.NumCPU() {
		runtime.GOMAXPROCS(2 * runtime.NumCPU())
	}
	// logging is unrequested output, whether it is debug information or error
	// details. Redirecting stdout to a file should result in a file that has
	// what the user requested and not a bunch of log messages _related_ to what
	// was asked for.
	logrus.SetOutput(os.Stderr)

	if os.Getenv("BINPRINT_PROFILE") != "" {
		runtime.SetBlockProfileRate(100)
		go http.ListenAndServe(":8910", nil)
		defer profile.Start().Stop()
	}
	return Execute()
}

func main() {
	// wrapping main allows us to use defer in realMain and still have them
	// executed even if we want to exit with a non-zero value, which requires
	// that we use os.Exit()
	if err := realMain(); err != nil {
		os.Exit(1)
	}
}
