/*
Copyright 2020 The Kubernetes Authors.

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

package bindata

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

func rawObjectToUnstructured(in string) (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{}
	dec := k8syaml.NewYAMLToJSONDecoder(strings.NewReader(in))
	if err := dec.Decode(obj); err != nil {
		return nil, fmt.Errorf("couldn't decode YAML: %w", err)
	}
	return obj, nil
}
