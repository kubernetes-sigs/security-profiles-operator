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

package utiltest

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// CounterValue returns the value of the counter series of the metric name
// with the label values, which one of the collectors collects. It returns
// zero if there is no such series.
func CounterValue(
	t *testing.T,
	collectors map[string]prometheus.Collector,
	name string,
	labels map[string]string,
) float64 {
	t.Helper()

	registry := prometheus.NewRegistry()
	for _, collector := range collectors {
		require.NoError(t, registry.Register(collector))
	}

	families, err := registry.Gather()
	require.NoError(t, err)

	for _, family := range families {
		if family.GetName() != name {
			continue
		}

		for _, metric := range family.GetMetric() {
			matches := len(metric.GetLabel()) == len(labels)
			for _, label := range metric.GetLabel() {
				matches = matches && labels[label.GetName()] == label.GetValue()
			}

			if matches {
				return metric.GetCounter().GetValue()
			}
		}
	}

	return 0
}
