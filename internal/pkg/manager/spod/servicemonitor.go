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
	"time"

	"github.com/go-logr/logr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// ServesServiceMonitors returns true if the cluster serves the ServiceMonitor
// API of the Prometheus operator. It returns an error if the mapper cannot
// tell, like ServesAdmissionPolicies.
func ServesServiceMonitors(mapper meta.RESTMapper) (bool, error) {
	return servesKinds(
		mapper, monitoringv1.SchemeGroupVersion.WithKind(monitoringv1.ServiceMonitorsKind),
	)
}

// serviceMonitorWatcher waits for the ServiceMonitor API, which the cluster
// did not serve when the operator started, and reconciles the SPODs once it
// shows up, so that their ServiceMonitor gets created. Nothing else
// reconciles the SPODs then.
type serviceMonitorWatcher struct {
	mapper   meta.RESTMapper
	interval time.Duration
	events   chan<- event.GenericEvent
	// served gets called once the API is served, before the SPODs get
	// reconciled.
	served func()
	log    logr.Logger
}

var _ manager.LeaderElectionRunnable = &serviceMonitorWatcher{}

// NeedLeaderElection returns true, because the SPOD controller only runs on
// the leader.
func (w *serviceMonitorWatcher) NeedLeaderElection() bool {
	return true
}

// Start checks every interval whether the API is served, and returns once it
// is or the context is done.
func (w *serviceMonitorWatcher) Start(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		served, err := ServesServiceMonitors(w.mapper)
		if err != nil {
			w.log.Error(err, "Cannot check whether the ServiceMonitor API is served")

			continue
		}

		if !served {
			continue
		}

		w.served()

		// The SPOD controller maps the event to all SPODs.
		select {
		case <-ctx.Done():
		case w.events <- event.GenericEvent{Object: &monitoringv1.ServiceMonitor{}}:
		}

		return nil
	}
}
