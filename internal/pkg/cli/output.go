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

import "os"

// Stdout is the output file name which writes to the standard output of spoc.
const Stdout = "/dev/stdout"

// WriteFile writes the data to the file like os.WriteFile, or to the standard
// output of spoc for Stdout. Opening /dev/stdout would truncate a file which
// stdout gets appended to, and fail for a socket.
func WriteFile(name string, data []byte, perm os.FileMode) error {
	if name == Stdout {
		_, err := os.Stdout.Write(data)

		return err
	}

	return os.WriteFile(name, data, perm)
}
