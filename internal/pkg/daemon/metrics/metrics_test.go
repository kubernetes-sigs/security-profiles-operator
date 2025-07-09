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

func TestRegister(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare   func(*metricsfakes.FakeImpl)
		shouldErr bool
	}{
		{ // success
			prepare: func(*metricsfakes.FakeImpl) {},
		},
		{ // error Register fails
			prepare: func(mock *metricsfakes.FakeImpl) {
				mock.RegisterReturns(errTest)
			},
			shouldErr: true,
		},
	} {
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
	}
}

func TestSeccompProfile(t *testing.T) {
	t.Parallel()

	getMetricValue := func(col prometheus.Collector) int {
		c := make(chan prometheus.Metric, 1)
		col.Collect(c)

		m := dto.Metric{}
		err := (<-c).Write(&m)
		require.NoError(t, err)

		return int(m.GetCounter().GetValue())
	}

	for _, tc := range []struct {
		when func(m *Metrics)
		then func(m *Metrics)
	}{
		{ // single update
			when: func(m *Metrics) {
				m.IncSeccompProfileUpdate()
			},
			then: func(m *Metrics) {
				ctr, err := m.metricSeccompProfile.GetMetricWithLabelValues(metricLabelValueProfileUpdate)
				require.NoError(t, err)
				require.Equal(t, 1, getMetricValue(ctr))
			},
		},
		{ // single delete
			when: func(m *Metrics) {
				m.IncSeccompProfileDelete()
			},
			then: func(m *Metrics) {
				ctr, err := m.metricSeccompProfile.GetMetricWithLabelValues(metricLabelValueProfileDelete)
				require.NoError(t, err)
				require.Equal(t, 1, getMetricValue(ctr))
			},
		},
		{ // multiple update and delete
			when: func(m *Metrics) {
				m.IncSeccompProfileUpdate()
				m.IncSeccompProfileUpdate()
				m.IncSeccompProfileDelete()
				m.IncSeccompProfileUpdate()
				m.IncSeccompProfileDelete()
			},
			then: func(m *Metrics) {
				ctrUpdate, err := m.metricSeccompProfile.GetMetricWithLabelValues(metricLabelValueProfileUpdate)
				require.NoError(t, err)
				require.Equal(t, 3, getMetricValue(ctrUpdate))

				ctrDelete, err := m.metricSeccompProfile.GetMetricWithLabelValues(metricLabelValueProfileDelete)
				require.NoError(t, err)
				require.Equal(t, 2, getMetricValue(ctrDelete))
			},
		},
		{ // Selinux single update
			when: func(m *Metrics) {
				m.IncSelinuxProfileUpdate()
			},
			then: func(m *Metrics) {
				ctr, err := m.metricSelinuxProfile.GetMetricWithLabelValues(metricLabelValueProfileUpdate)
				require.NoError(t, err)
				require.Equal(t, 1, getMetricValue(ctr))
			},
		},
		{ // Selinux single delete
			when: func(m *Metrics) {
				m.IncSelinuxProfileDelete()
			},
			then: func(m *Metrics) {
				ctr, err := m.metricSelinuxProfile.GetMetricWithLabelValues(metricLabelValueProfileDelete)
				require.NoError(t, err)
				require.Equal(t, 1, getMetricValue(ctr))
			},
		},
		{ // Selinux multiple update and delete
			when: func(m *Metrics) {
				m.IncSelinuxProfileUpdate()
				m.IncSelinuxProfileUpdate()
				m.IncSelinuxProfileDelete()
				m.IncSelinuxProfileUpdate()
				m.IncSelinuxProfileDelete()
			},
			then: func(m *Metrics) {
				ctrUpdate, err := m.metricSelinuxProfile.GetMetricWithLabelValues(metricLabelValueProfileUpdate)
				require.NoError(t, err)
				require.Equal(t, 3, getMetricValue(ctrUpdate))

				ctrDelete, err := m.metricSelinuxProfile.GetMetricWithLabelValues(metricLabelValueProfileDelete)
				require.NoError(t, err)
				require.Equal(t, 2, getMetricValue(ctrDelete))
			},
		},
	} {
		mock := &metricsfakes.FakeImpl{}
		sut := New()
		sut.impl = mock

		tc.when(sut)
		tc.then(sut)
	}
}

func TestSeccompProfileBpf(t *testing.T) {
	t.Parallel()

	const (
		node           = "node"
		profile        = "profile"
		mountNamespace = 1
	)

	getMetricValue := func(col prometheus.Collector) int {
		c := make(chan prometheus.Metric, 1)
		col.Collect(c)

		m := dto.Metric{}
		err := (<-c).Write(&m)
		require.NoError(t, err)

		return int(m.GetCounter().GetValue())
	}

	for _, tc := range []struct {
		when func(m *Metrics)
		then func(m *Metrics)
	}{
		{ // single update
			when: func(m *Metrics) {
				m.IncSeccompProfileBpf(node, profile, mountNamespace)
			},
			then: func(m *Metrics) {
				ctr, err := m.metricSeccompProfileBpf.GetMetricWithLabelValues(
					node, strconv.Itoa(mountNamespace), profile,
				)
				require.NoError(t, err)
				require.Equal(t, 1, getMetricValue(ctr))
			},
		},
		{ // multiple update
			when: func(m *Metrics) {
				m.IncSeccompProfileBpf(node, profile, mountNamespace)
				m.IncSeccompProfileBpf(node, profile, mountNamespace)
				m.IncSeccompProfileBpf(node, profile, mountNamespace)
			},
			then: func(m *Metrics) {
				ctrUpdate, err := m.metricSeccompProfileBpf.GetMetricWithLabelValues(
					node, strconv.Itoa(mountNamespace), profile,
				)
				require.NoError(t, err)
				require.Equal(t, 3, getMetricValue(ctrUpdate))
			},
		},
	} {
		mock := &metricsfakes.FakeImpl{}
		sut := New()
		sut.impl = mock

		tc.when(sut)
		tc.then(sut)
	}
}
