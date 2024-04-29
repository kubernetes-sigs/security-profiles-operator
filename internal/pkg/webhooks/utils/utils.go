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

package utils

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AppendIfNotExists adds an item to the provided list if it not exists.
func AppendIfNotExists(list []string, item string) []string {
	for _, s := range list {
		if s == item {
			return list
		}
	}
	return append(list, item)
}

// RemoveIfExists removes an item from the provided list if it exists.
func RemoveIfExists(list []string, item string) []string {
	for i := range list {
		if list[i] == item {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// UpdateResource tries to update the provided object by using the
// client.Writer. If the update fails, it automatically logs to the
// provided logger.
func UpdateResource(
	ctx context.Context,
	logger logr.Logger,
	c client.Writer,
	object client.Object,
	name string,
) error {
	if err := c.Update(ctx, object); err != nil {
		msg := "failed to update resource " + name
		logger.Error(err, msg)
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}

// UpdateResourceStatus tries to update the provided object by using the
// client.StatusWriter. If the update fails, it automatically logs to the
// provided logger.
func UpdateResourceStatus(
	ctx context.Context,
	logger logr.Logger,
	c client.StatusWriter,
	object client.Object,
	name string,
) error {
	if err := c.Update(ctx, object); err != nil {
		msg := "failed to update resource " + name
		logger.Error(err, msg)
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}
