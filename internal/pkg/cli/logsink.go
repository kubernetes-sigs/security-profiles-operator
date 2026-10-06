/*
Copyright The Kubernetes Authors.

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
	"slices"
	"strings"

	"github.com/go-logr/logr"
)

// missingValue is printed for the value of a key without one.
const missingValue = "<no value>"

// LogSink is the logr.LogSink of spoc, which prints through the standard
// logger: the name, the message, the error and the key/value pairs.
type LogSink struct {
	name   string
	values []any
}

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
func (l *LogSink) Info(_ int, msg string, keysAndValues ...any) {
	l.Print(msg, nil, keysAndValues...)
}

// Error logs an error, with the given message and key/value pairs as
// context.  See Logger.Error for more details.
func (l *LogSink) Error(err error, msg string, keysAndValues ...any) {
	l.Print(msg, err, keysAndValues...)
}

// Print logs the message with the error, if any, and the key/value pairs of
// the sink followed by the given ones.
func (l *LogSink) Print(msg string, err error, keysAndValues ...any) {
	log.Print(l.format(msg, err, keysAndValues...))
}

// format returns the log line: `name: msg, err: err (key=value, ...)`. A key
// without a value gets missingValue.
func (l *LogSink) format(msg string, err error, keysAndValues ...any) string {
	builder := strings.Builder{}

	if l.name != "" {
		builder.WriteString(l.name)
		builder.WriteString(": ")
	}

	builder.WriteString(msg)

	if err != nil {
		fmt.Fprintf(&builder, ", err: %v", err)
	}

	values := slices.Concat(l.values, keysAndValues)
	if len(values) == 0 {
		return builder.String()
	}

	builder.WriteString(" (")

	for i := 0; i < len(values); i += 2 {
		if i > 0 {
			builder.WriteString(", ")
		}

		var value any = missingValue
		if i+1 < len(values) {
			value = values[i+1]
		}

		fmt.Fprintf(&builder, "%v=%v", values[i], value)
	}

	builder.WriteRune(')')

	return builder.String()
}

// WithValues returns a new LogSink with additional key/value pairs.  See
// Logger.WithValues for more details.
func (l *LogSink) WithValues(keysAndValues ...any) logr.LogSink {
	return &LogSink{
		name:   l.name,
		values: slices.Concat(l.values, keysAndValues),
	}
}

// WithName returns a new LogSink with the specified name appended.  See
// Logger.WithName for more details.
func (l *LogSink) WithName(name string) logr.LogSink {
	if l.name != "" {
		name = l.name + "/" + name
	}

	return &LogSink{
		name:   name,
		values: slices.Clone(l.values),
	}
}
