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
	"errors"
	"io"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

// Stdout is the output file name which writes to the standard output of spoc.
const Stdout = "/dev/stdout"

// StandardStream returns the standard output or error of spoc if the output
// file name refers to one of them, like /dev/stdout, /dev/fd/2 or
// /proc/thread-self/fd/1, or to the file one of them is open on. Opening such
// a path would truncate a file which the stream gets appended to, or which the
// other stream shares, and fail for a socket.
func StandardStream(name string) (*os.File, bool) {
	// The well known names also work while the stream cannot be checked,
	// like after it got closed.
	switch filepath.Clean(name) {
	case Stdout, "/dev/fd/1", "/proc/self/fd/1":
		return os.Stdout, true
	case "/dev/stderr", "/dev/fd/2", "/proc/self/fd/2":
		return os.Stderr, true
	}

	target, err := os.Stat(name)
	if err != nil {
		return nil, false
	}

	for _, stream := range []*os.File{os.Stdout, os.Stderr} {
		if info, err := stream.Stat(); err == nil && os.SameFile(target, info) {
			return stream, true
		}
	}

	return nil, false
}

// WriteFile writes the data to the file like os.WriteFile, or to the standard
// output or error of spoc for the names of StandardStream.
func WriteFile(name string, data []byte, perm os.FileMode) error {
	if stream, ok := StandardStream(name); ok {
		_, err := stream.Write(data)

		return err
	}

	return os.WriteFile(name, data, perm)
}

var errMissingKind = errors.New(
	"missing apiVersion or kind; try GetObjectKind().SetGroupVersionKind() if you know the type",
)

// PrintYAML writes the object as YAML, like the YAML printer of kubectl does
// for a single object.
func PrintYAML(obj runtime.Object, w io.Writer) error {
	if obj.GetObjectKind().GroupVersionKind().Empty() {
		return errMissingKind
	}

	output, err := yaml.Marshal(obj)
	if err != nil {
		return err
	}

	_, err = w.Write(output)

	return err
}
