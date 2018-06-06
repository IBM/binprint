// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package record

// object-a was created by event-a; eg. "program.exe" was created by "build 1234"
// object-a imports object-b; eg. "program.exe" depends on "main.c"
// object-a includes object-c; eg. "program.zip" embeds an extractable copy of "program.exe"

type includes struct {
	source      *Fingerprint
	destination *Fingerprint
}

type imports struct {
	source      *Fingerprint
	destination *Fingerprint
}

type creates struct {
	source      *event
	destination *Fingerprint
}

type event struct {
	// timestamp?
	// name?
	// description?
	// location?
}
