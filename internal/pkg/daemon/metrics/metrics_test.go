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
	"errors"
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics/metricsfakes"
)

var errTest = errors.New("")

// getMetricValue returns the value of the single counter which col collects.
func getMetricValue(t *testing.T, col prometheus.Collector) int {
	t.Helper()

	c := make(chan prometheus.Metric, 1)
	col.Collect(c)

	m := dto.Metric{}
	require.NoError(t, (<-c).Write(&m))

	return int(m.GetCounter().GetValue())
}

func TestRegister(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		prepare   func(*metricsfakes.FakeImpl)
		shouldErr bool
	}{
		{
			name:    "success",
			prepare: func(*metricsfakes.FakeImpl) {},
		},
		{
			name: "error Register fails",
			prepare: func(mock *metricsfakes.FakeImpl) {
				mock.RegisterReturns(errTest)
			},
			shouldErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &metricsfakes.FakeImpl{}
			tc.prepare(mock)

			sut := New()
			sut.impl = mock

			err := sut.Register()

			if tc.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSeccompProfile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		when func(m *Metrics)
		then func(t *testing.T, m *Metrics)
	}{
		{
			name: "single update",
			when: func(m *Metrics) {
				m.IncSeccompProfileUpdate()
			},
			then: func(t *testing.T, m *Metrics) {
				t.Helper()

				ctr, err := m.metricSeccompProfile.GetMetricWithLabelValues(metricLabelValueProfileUpdate)
				require.NoError(t, err)
				require.Equal(t, 1, getMetricValue(t, ctr))
			},
		},
		{
			name: "single delete",
			when: func(m *Metrics) {
				m.IncSeccompProfileDelete()
			},
			then: func(t *testing.T, m *Metrics) {
				t.Helper()

				ctr, err := m.metricSeccompProfile.GetMetricWithLabelValues(metricLabelValueProfileDelete)
				require.NoError(t, err)
				require.Equal(t, 1, getMetricValue(t, ctr))
			},
		},
		{
			name: "multiple update and delete",
			when: func(m *Metrics) {
				m.IncSeccompProfileUpdate()
				m.IncSeccompProfileUpdate()
				m.IncSeccompProfileDelete()
				m.IncSeccompProfileUpdate()
				m.IncSeccompProfileDelete()
			},
			then: func(t *testing.T, m *Metrics) {
				t.Helper()

				ctrUpdate, err := m.metricSeccompProfile.GetMetricWithLabelValues(metricLabelValueProfileUpdate)
				require.NoError(t, err)
				require.Equal(t, 3, getMetricValue(t, ctrUpdate))

				ctrDelete, err := m.metricSeccompProfile.GetMetricWithLabelValues(metricLabelValueProfileDelete)
				require.NoError(t, err)
				require.Equal(t, 2, getMetricValue(t, ctrDelete))
			},
		},
		{
			name: "Selinux single update",
			when: func(m *Metrics) {
				m.IncSelinuxProfileUpdate()
			},
			then: func(t *testing.T, m *Metrics) {
				t.Helper()

				ctr, err := m.metricSelinuxProfile.GetMetricWithLabelValues(metricLabelValueProfileUpdate)
				require.NoError(t, err)
				require.Equal(t, 1, getMetricValue(t, ctr))
			},
		},
		{
			name: "Selinux single delete",
			when: func(m *Metrics) {
				m.IncSelinuxProfileDelete()
			},
			then: func(t *testing.T, m *Metrics) {
				t.Helper()

				ctr, err := m.metricSelinuxProfile.GetMetricWithLabelValues(metricLabelValueProfileDelete)
				require.NoError(t, err)
				require.Equal(t, 1, getMetricValue(t, ctr))
			},
		},
		{
			name: "Selinux multiple update and delete",
			when: func(m *Metrics) {
				m.IncSelinuxProfileUpdate()
				m.IncSelinuxProfileUpdate()
				m.IncSelinuxProfileDelete()
				m.IncSelinuxProfileUpdate()
				m.IncSelinuxProfileDelete()
			},
			then: func(t *testing.T, m *Metrics) {
				t.Helper()

				ctrUpdate, err := m.metricSelinuxProfile.GetMetricWithLabelValues(metricLabelValueProfileUpdate)
				require.NoError(t, err)
				require.Equal(t, 3, getMetricValue(t, ctrUpdate))

				ctrDelete, err := m.metricSelinuxProfile.GetMetricWithLabelValues(metricLabelValueProfileDelete)
				require.NoError(t, err)
				require.Equal(t, 2, getMetricValue(t, ctrDelete))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut := New()
			sut.impl = &metricsfakes.FakeImpl{}

			tc.when(sut)
			tc.then(t, sut)
		})
	}
}

func TestSeccompProfileBpf(t *testing.T) {
	t.Parallel()

	const (
		node           = "node"
		profile        = "profile"
		mountNamespace = 1
	)

	for _, tc := range []struct {
		name string
		when func(m *Metrics)
		then func(t *testing.T, m *Metrics)
	}{
		{
			name: "single update",
			when: func(m *Metrics) {
				m.IncSeccompProfileBpf(node, profile, mountNamespace)
			},
			then: func(t *testing.T, m *Metrics) {
				t.Helper()

				ctr, err := m.metricSeccompProfileBpf.GetMetricWithLabelValues(
					node, strconv.Itoa(mountNamespace), profile,
				)
				require.NoError(t, err)
				require.Equal(t, 1, getMetricValue(t, ctr))
			},
		},
		{
			name: "multiple update",
			when: func(m *Metrics) {
				m.IncSeccompProfileBpf(node, profile, mountNamespace)
				m.IncSeccompProfileBpf(node, profile, mountNamespace)
				m.IncSeccompProfileBpf(node, profile, mountNamespace)
			},
			then: func(t *testing.T, m *Metrics) {
				t.Helper()

				ctrUpdate, err := m.metricSeccompProfileBpf.GetMetricWithLabelValues(
					node, strconv.Itoa(mountNamespace), profile,
				)
				require.NoError(t, err)
				require.Equal(t, 3, getMetricValue(t, ctrUpdate))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut := New()
			sut.impl = &metricsfakes.FakeImpl{}

			tc.when(sut)
			tc.then(t, sut)
		})
	}
}

// The AppArmor error counter is labeled by profile and reason, which existing
// queries rely on.
func TestAppArmorProfileError(t *testing.T) {
	t.Parallel()

	sut := New()
	sut.IncAppArmorProfileError("profile", "CannotLoadAppArmorProfile")
	sut.IncAppArmorProfileError("profile", "CannotLoadAppArmorProfile")
	sut.IncAppArmorProfileError("other", "AppArmorNotSupportedOnNode")

	ctr, err := sut.metricAppArmorProfileError.GetMetricWithLabelValues(
		"profile", "CannotLoadAppArmorProfile")
	require.NoError(t, err)

	m := dto.Metric{}
	require.NoError(t, ctr.Write(&m))
	require.InDelta(t, 2, m.GetCounter().GetValue(), 0)
	require.Len(t, m.GetLabel(), 2)

	ctr, err = sut.metricAppArmorProfileError.GetMetricWithLabelValues(
		"other", "AppArmorNotSupportedOnNode")
	require.NoError(t, err)
	require.NoError(t, ctr.Write(&m))
	require.InDelta(t, 1, m.GetCounter().GetValue(), 0)
}
