// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package store

import (
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var logger = logrus.New()
var log logrus.FieldLogger

func init() {
	log = logger.WithField("prefix", "cache")
	logger.Formatter = new(prefixed.TextFormatter)
	logger.Level = logrus.DebugLevel
}
