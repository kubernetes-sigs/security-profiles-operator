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

package spod

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// installableMapper is a RESTMapper which knows the ServiceMonitor kind once
// it got installed.
type installableMapper struct {
	meta.RESTMapper

	installed atomic.Bool
	lookups   atomic.Int32
}

func newInstallableMapper() *installableMapper {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(
		monitoringv1.SchemeGroupVersion.WithKind(monitoringv1.ServiceMonitorsKind),
		meta.RESTScopeNamespace,
	)

	return &installableMapper{RESTMapper: mapper}
}

func (m *installableMapper) RESTMapping(
	gk schema.GroupKind, versions ...string,
) (*meta.RESTMapping, error) {
	m.lookups.Add(1)

	if !m.installed.Load() {
		return nil, &meta.NoKindMatchError{GroupKind: gk}
	}

	return m.RESTMapper.RESTMapping(gk, versions...)
}

// The SPODs used to get no ServiceMonitor for an API installed after the
// operator started, until something else reconciled them.
func TestServiceMonitorWatcher(t *testing.T) {
	t.Parallel()

	mapper := newInstallableMapper()
	events := make(chan event.GenericEvent)
	served := atomic.Bool{}

	w := &serviceMonitorWatcher{
		mapper:   mapper,
		interval: time.Millisecond,
		events:   events,
		served:   func() { served.Store(true) },
		log:      logr.Discard(),
	}

	done := make(chan error)

	go func() { done <- w.Start(t.Context()) }()

	// The watcher keeps checking while the API is missing.
	require.Eventually(
		t,
		func() bool { return mapper.lookups.Load() > 2 },
		time.Second,
		time.Millisecond,
	)
	require.False(t, served.Load())

	mapper.installed.Store(true)

	select {
	case <-events:
	case <-time.After(time.Second):
		require.Fail(t, "no event for the installed API")
	}

	require.True(t, served.Load())
	require.NoError(t, <-done)
}

func TestServiceMonitorWatcherStopsWithTheContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	w := &serviceMonitorWatcher{
		mapper:   newInstallableMapper(),
		interval: time.Millisecond,
		events:   make(chan event.GenericEvent),
		served:   func() {},
		log:      logr.Discard(),
	}

	done := make(chan error)

	go func() { done <- w.Start(ctx) }()

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		require.Fail(t, "the watcher did not stop")
	}

	require.True(t, w.NeedLeaderElection())
}
