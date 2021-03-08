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

package util

import (
	"fmt"

	"github.com/pkg/errors"
)

// retry attempts to execute fn up to 5 times if its failure meets retryCondition.
func Retry(fn func() error, retryCondition func(error) bool) error {
	const retries = 5
	var err error
	for i := 0; i < retries; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		if !retryCondition(err) {
			return errors.Wrap(err, "failed retry")
		}
	}
	return errors.Wrap(err, fmt.Sprintf("exceeded %d retries", retries))
}
