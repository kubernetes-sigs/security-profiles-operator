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

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// seriesCount returns the number of series of a metric.
func seriesCount(vec *prometheus.CounterVec) int {
	ch := make(chan prometheus.Metric, 100)
	vec.Collect(ch)
	close(ch)

	return len(ch)
}

// TestSeriesExpire asserts that the series of the per workload metrics are
// dropped once they were not incremented for a while, and only those.
func TestSeriesExpire(t *testing.T) {
	t.Parallel()

	sut := New()

	now := time.Now()
	sut.series.now = func() time.Time { return now }

	sut.IncSeccompProfileAudit("node", "ns", "gone", "ctr", "read")
	sut.IncSeccompProfileBpf("node", "profile", 1)
	sut.IncAppArmorProfileAudit("node", "ns", "gone", "ctr", "profile", "open", "DENIED")
	sut.IncSelinuxProfileAudit("node", "ns", "gone", "ctr", "s", "t")

	now = now.Add(seriesTTL / 2)

	sut.IncSeccompProfileAudit("node", "ns", "running", "ctr", "read")

	now = now.Add(seriesTTL/2 + time.Second)

	sut.series.expire()

	require.Equal(t, 1, seriesCount(sut.metricSeccompProfileAudit))

	value := dto.Metric{}
	require.NoError(t, sut.metricSeccompProfileAudit.
		WithLabelValues("node", "ns", "running", "ctr", "read").Write(&value))
	require.InDelta(t, 1, value.GetCounter().GetValue(), 0)
	require.Zero(t, seriesCount(sut.metricSeccompProfileBpf))
	require.Zero(t, seriesCount(sut.metricAppArmorProfileAudit))
	require.Zero(t, seriesCount(sut.metricSelinuxProfileAudit))

	// Denials are not per workload.
	require.Equal(t, 1, seriesCount(sut.metricAppArmorProfileDenial))
	require.Len(t, sut.series.series, 1)
}
