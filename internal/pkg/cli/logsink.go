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

package cli

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-logr/logr"
)

type LogSink struct{}

// Init receives optional information about the logr library for LogSink
// implementations that need it.
func (*LogSink) Init(logr.RuntimeInfo) {}

// Enabled tests whether this LogSink is enabled at the specified V-level.
// For example, commandline flags might be used to set the logging
// verbosity and disable some info logs.
func (*LogSink) Enabled(level int) bool {
	return level <= 0
}

// Info logs a non-error message with the given key/value pairs as context.
// The level argument is provided for optional logging.  This method will
// only be called when Enabled(level) is true. See Logger.Info for more
// details.
func (l *LogSink) Info(_ int, msg string, keysAndValues ...interface{}) {
	l.Print(msg, nil, keysAndValues...)
}

// Error logs an error, with the given message and key/value pairs as
// context.  See Logger.Error for more details.
func (l *LogSink) Error(err error, msg string, keysAndValues ...interface{}) {
	l.Print(msg, err, keysAndValues...)
}

func (*LogSink) Print(msg string, err error, keysAndValues ...interface{}) {
	builder := strings.Builder{}
	builder.WriteString(msg)

	if err != nil {
		builder.WriteString(fmt.Sprintf(", err: %v", err))
	}

	for i, kv := range keysAndValues {
		if i == 0 {
			builder.WriteString(" (")
		}

		builder.WriteString(fmt.Sprintf("%v", kv))
		//nolint:gocritic // this is intentionally an else-if-chain
		if i%2 == 0 {
			builder.WriteRune('=')
		} else if i == len(keysAndValues)-1 {
			builder.WriteRune(')')
		} else {
			builder.WriteString(", ")
		}
	}

	log.Print(builder.String())
}

// WithValues returns a new LogSink with additional key/value pairs.  See
// Logger.WithValues for more details.
func (*LogSink) WithValues(...interface{}) logr.LogSink {
	return &LogSink{}
}

// WithName returns a new LogSink with the specified name appended.  See
// Logger.WithName for more details.
func (l *LogSink) WithName(string) logr.LogSink {
	return &LogSink{}
}
