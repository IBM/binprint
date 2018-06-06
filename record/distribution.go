// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package record

// Distribution is a collection of objects packaged together in some form. A
// Distribution is similar to an archive but does not require that an actual
// archive exist. An example of a distribution is all of the materials published
// as part of a release.
type Distribution struct {
	Name        string
	Description string
	Files       []*File
}
