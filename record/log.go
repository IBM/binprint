// Copyright 2018 IBM Corporation
// Licensed under the Apache License, Version 2.0. See LICENSE file.

package record

import (
	"github.com/sirupsen/logrus"
	"github.com/x-cray/logrus-prefixed-formatter"
)

var logger = logrus.New()
var log logrus.FieldLogger

func init() {
	log = logger.WithField("prefix", "container")
	logger.Formatter = new(prefixed.TextFormatter)
	logger.Level = logrus.DebugLevel
}
