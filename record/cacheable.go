// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package record

// embeddedCacheID is a type to embed in a struct to implement a cache id aware
// interface without having to define caching semantics in this package
type embeddedCacheID struct {
	id    uint64
	hasID bool
}

func (c embeddedCacheID) IsCached() bool {
	return c.hasID
}

func (c embeddedCacheID) CacheID() uint64 {
	return c.id
}

func (c *embeddedCacheID) SetCacheID(id uint64) {
	c.hasID = true
	c.id = id
}
