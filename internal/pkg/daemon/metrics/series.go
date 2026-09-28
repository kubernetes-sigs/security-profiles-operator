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
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// seriesTTL is how long a series of a per workload metric is kept after
	// it was last incremented. Their labels contain values like the pod name
	// or the mount namespace, which change with every pod, so the series
	// would pile up for the lifetime of the daemon otherwise.
	seriesTTL = time.Hour

	// seriesExpiryInterval is how often the idle series are dropped.
	seriesExpiryInterval = 5 * time.Minute
)

// seriesKey identifies a series of a metric.
type seriesKey struct {
	vec *prometheus.CounterVec
	// labels are the joined label values.
	labels string
}

type seriesEntry struct {
	labels   []string
	lastSeen time.Time
}

// seriesTracker drops the series of counters which were not incremented for
// seriesTTL. Prometheus handles a counter which starts over as a reset.
type seriesTracker struct {
	mu     sync.Mutex
	series map[seriesKey]*seriesEntry
	now    func() time.Time
}

func newSeriesTracker() *seriesTracker {
	return &seriesTracker{
		series: map[seriesKey]*seriesEntry{},
		now:    time.Now,
	}
}

// inc increments the series of vec with the label values.
func (t *seriesTracker) inc(vec *prometheus.CounterVec, labels ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Incrementing under the lock keeps expire from deleting the series in
	// between.
	vec.WithLabelValues(labels...).Inc()

	// A label value is valid UTF-8, which never contains 0xff.
	key := seriesKey{vec: vec, labels: strings.Join(labels, "\xff")}

	entry, ok := t.series[key]
	if !ok {
		entry = &seriesEntry{labels: labels}
		t.series[key] = entry
	}

	entry.lastSeen = t.now()
}

// expire drops the series which were not incremented for seriesTTL.
func (t *seriesTracker) expire() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := t.now().Add(-seriesTTL)

	for key, entry := range t.series {
		if entry.lastSeen.Before(cutoff) {
			key.vec.DeleteLabelValues(entry.labels...)
			delete(t.series, key)
		}
	}
}

// run drops idle series until stop is closed.
func (t *seriesTracker) run(stop <-chan struct{}) {
	ticker := time.NewTicker(seriesExpiryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			t.expire()
		}
	}
}
