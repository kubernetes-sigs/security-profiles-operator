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

	// DefaultMaxSeries is the default number of series a per workload metric
	// keeps at most. The limit drops increments of existing metrics, so it
	// is opt-in and zero keeps any number by default.
	DefaultMaxSeries = 0

	// seriesDropLogInterval is how many dropped increments of a metric are
	// logged once.
	seriesDropLogInterval = 1000
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

// seriesStats is the bookkeeping of the series of a metric.
type seriesStats struct {
	// live is the number of tracked series.
	live int
	// dropped is the number of increments of new series which got dropped
	// for exceeding maxSeries.
	dropped uint64
}

// seriesTracker drops the series of counters which were not incremented for
// seriesTTL. Prometheus handles a counter which starts over as a reset. It
// also limits the number of series per metric, as the expiry alone does not
// bound them on a node with a lot of workload churn.
type seriesTracker struct {
	mu     sync.Mutex
	series map[seriesKey]*seriesEntry
	counts map[*prometheus.CounterVec]*seriesStats
	// maxSeries is the number of series a metric keeps at most, zero keeps
	// any number.
	maxSeries int
	now       func() time.Time
}

func newSeriesTracker() *seriesTracker {
	return &seriesTracker{
		series:    map[seriesKey]*seriesEntry{},
		counts:    map[*prometheus.CounterVec]*seriesStats{},
		maxSeries: DefaultMaxSeries,
		now:       time.Now,
	}
}

// setMaxSeries sets the number of series a metric keeps at most, zero keeps
// any number.
func (t *seriesTracker) setMaxSeries(maxSeries int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.maxSeries = maxSeries
}

// inc increments the series of vec with the label values. A new series which
// exceeds the limit of series is not created. inc then returns the number of
// increments of vec dropped so far, and zero otherwise.
func (t *seriesTracker) inc(vec *prometheus.CounterVec, labels ...string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	// A label value is valid UTF-8, which never contains 0xff.
	key := seriesKey{vec: vec, labels: strings.Join(labels, "\xff")}

	count, ok := t.counts[vec]
	if !ok {
		count = &seriesStats{}
		t.counts[vec] = count
	}

	entry, ok := t.series[key]
	if !ok {
		if t.maxSeries > 0 && count.live >= t.maxSeries {
			count.dropped++

			return count.dropped
		}

		entry = &seriesEntry{labels: labels}
		t.series[key] = entry
		count.live++
	}

	// Incrementing under the lock keeps expire from deleting the series in
	// between.
	vec.WithLabelValues(labels...).Inc()

	entry.lastSeen = t.now()

	return 0
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

			t.counts[key.vec].live--
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
