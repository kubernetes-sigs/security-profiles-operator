/*
Copyright 2021 The Kubernetes Authors.

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
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	backoffDuration = 500 * time.Millisecond
	backoffFactor   = 1.5
	backoffSteps    = 5
)

func IsNotFoundOrConflict(err error) bool {
	return errors.IsNotFound(err) || errors.IsConflict(err)
}

// retry attempts to execute fn up to 5 times if its failure meets retryCondition.
func Retry(fn func() error, retryCondition func(error) bool) error {
	backoff := wait.Backoff{
		Duration: backoffDuration,
		Factor:   backoffFactor,
		Steps:    backoffSteps,
	}

	return RetryEx(&backoff, fn, retryCondition)
}

func RetryEx(backoff *wait.Backoff, fn func() error, retryCondition func(error) bool) error {
	waitErr := wait.ExponentialBackoff(*backoff, func() (bool, error) {
		err := fn()
		if err == nil {
			return true, nil
		} else if retryCondition(err) {
			return false, nil
		}

		return false, fmt.Errorf("retry function: %w", err)
	})
	if waitErr != nil {
		return fmt.Errorf("wait on retry: %w", waitErr)
	}

	return nil
}
