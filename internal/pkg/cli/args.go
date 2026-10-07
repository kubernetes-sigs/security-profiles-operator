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
	"log"
	"strings"
)

// WarnExtraArgs logs the positional arguments after the first n, which the
// command ignores. A mistyped invocation, like a file passed as an argument
// instead of with its flag, gets noticed this way. Rejecting them would change
// the exit code of invocations which work today.
func WarnExtraArgs(args []string, n int) {
	if len(args) > n {
		log.Printf("Ignoring extra arguments: %s", strings.Join(args[n:], " "))
	}
}
