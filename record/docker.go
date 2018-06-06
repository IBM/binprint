// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package record

// DockerImage is a top-level object containing multiple children. Note that it
// does not include a Fingerprint property. This is because Docker does not use
// any sort of consistent representation for its images and thus a Fingerprint
// can only ever map to a specific run of `docker save` which makes it very
// useless.
type DockerImage struct {
	Name            string
	Layers          []*DockerLayer
	RepoDigests     []string
	ImageID         string
	embeddedCacheID `yaml:"-"`
}

// DockerLayer represents a docker image layer, which consists primarily of files
type DockerLayer struct {
	Name   string
	TarSum string
	Files  []*File
	// Fingerprint here refers to a fingerprint of the tar stream that was read
	// to extract the layer contents. It does not map to any canonical image or
	// layer identifier because Docker does not support consistent hashing.
	Fingerprint *Fingerprint
}
