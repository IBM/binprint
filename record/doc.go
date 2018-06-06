// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

/*
Package record contains the highlevel types used for tracking fingerprinted
blobs. These blobs are typically stored as files, but the same content may also
be present in an archive file, docker image, git repo, or some other format
where the original content can be retrieved but isn't necessarily stored in the
same representation a the original blob (eg, it may be compressed).
*/
package record
