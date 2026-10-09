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

package util

import (
	ggcrname "github.com/google/go-containerregistry/pkg/name"
)

// NormalizeImage returns the fully qualified form of the image reference,
// which the container runtime pulls: images without a registry come from
// Docker Hub, official Docker Hub images get the library/ namespace, and
// references without a tag or digest get the latest tag. A reference with a
// tag and a digest gets pulled by its digest, so the tag is dropped. A
// reference which does not parse is returned unchanged, so that it still
// matches the identical string.
func NormalizeImage(image string) string {
	ref, err := ggcrname.ParseReference(image)
	if err != nil {
		return image
	}

	return ref.Name()
}

// SameImage returns true if both image references resolve to the same image.
func SameImage(a, b string) bool {
	return a == b || NormalizeImage(a) == NormalizeImage(b)
}
