/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package recorder

import (
	"log"

	"github.com/go-logr/logr"
)

type LogSink struct{}

// Init receives optional information about the logr library for LogSink
// implementations that need it.
func (*LogSink) Init(info logr.RuntimeInfo) {}

// Enabled tests whether this LogSink is enabled at the specified V-level.
// For example, commandline flags might be used to set the logging
// verbosity and disable some info logs.
func (*LogSink) Enabled(level int) bool {
	return true
}

// Info logs a non-error message with the given key/value pairs as context.
// The level argument is provided for optional logging.  This method will
// only be called when Enabled(level) is true. See Logger.Info for more
// details.
func (*LogSink) Info(level int, msg string, keysAndValues ...interface{}) {
	log.Print(msg)
}

// Error logs an error, with the given message and key/value pairs as
// context.  See Logger.Error for more details.
func (*LogSink) Error(err error, msg string, keysAndValues ...interface{}) {
	log.Print(msg)
}

// WithValues returns a new LogSink with additional key/value pairs.  See
// Logger.WithValues for more details.
func (*LogSink) WithValues(keysAndValues ...interface{}) logr.LogSink {
	return &LogSink{}
}

// WithName returns a new LogSink with the specified name appended.  See
// Logger.WithName for more details.
func (l *LogSink) WithName(name string) logr.LogSink {
	return &LogSink{}
}
