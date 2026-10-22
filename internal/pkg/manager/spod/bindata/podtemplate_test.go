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

package bindata

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func Test_containerListsDiffer(t *testing.T) {
	t.Parallel()

	base := []corev1.Container{{
		Args:         []string{"a"},
		Env:          []corev1.EnvVar{{Name: "E"}},
		VolumeMounts: []corev1.VolumeMount{{Name: "v"}},
	}}

	require.False(t, containerListsDiffer(base, base))
	require.False(t, containerListsDiffer(nil, nil))

	for name, mutate := range map[string]func(*corev1.Container){
		"args":         func(c *corev1.Container) { c.Args = nil },
		"env":          func(c *corev1.Container) { c.Env = append(c.Env, corev1.EnvVar{Name: "F"}) },
		"volumeMounts": func(c *corev1.Container) { c.VolumeMounts = nil },
	} {
		found := []corev1.Container{*base[0].DeepCopy()}
		mutate(&found[0])
		require.True(t, containerListsDiffer(base, found), name)
	}

	// Only the lengths are compared, the content is left to DeepDerivative.
	found := []corev1.Container{*base[0].DeepCopy()}
	found[0].Args = []string{"b"}
	require.False(t, containerListsDiffer(base, found))
}

// The webhook deployment gets compared like the DaemonSet, so that a limit
// which a release removes gets removed from the stored deployment as well.
func TestDeploymentNeedsUpdateRemovedLimit(t *testing.T) {
	t.Parallel()

	configured := webhookDeployment.DeepCopy()
	found := configured.DeepCopy()
	require.False(t, deploymentNeedsUpdate(configured, found))

	found.Spec.Template.Spec.Containers[0].Resources.Limits = corev1.ResourceList{
		corev1.ResourceCPU: resource.MustParse("1"),
	}
	configured.Spec.Template.Spec.Containers[0].Resources.Limits = nil
	require.True(t, deploymentNeedsUpdate(configured, found))
}
