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

package utils

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IsWindowsPod reports whether the pod declares the Windows operating system.
// The API server rejects seccomp, SELinux and AppArmor settings on such pods,
// so the mutating webhooks have to leave them alone.
func IsWindowsPod(pod *corev1.Pod) bool {
	return pod != nil && pod.Spec.OS != nil && pod.Spec.OS.Name == corev1.Windows
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
