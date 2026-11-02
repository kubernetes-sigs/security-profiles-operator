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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegistryReference(t *testing.T) {
	t.Parallel()

	for arg, want := range map[string]string{
		"registry.k8s.io/spo/profile:v1":         "registry.k8s.io/spo/profile:v1",
		"oci://registry.k8s.io/spo/profile:v1":   "registry.k8s.io/spo/profile:v1",
		"localhost:5000/profile@sha256:abcdef01": "localhost:5000/profile@sha256:abcdef01",
	} {
		require.Equal(t, want, RegistryReference(arg), arg)
	}
}
