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

package enricher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"k8s.io/client-go/tools/cache"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// exitedProcessTimeout is how long the container of a process is kept
	// for the audit lines read after the process exited. The audit log is
	// read with a delay, so a short lived process is often gone before its
	// lines are processed. The container is only used while no process with
	// the PID exists, so another process could get lines of a gone one only
	// if it reused the PID and exited again within this time.
	exitedProcessTimeout time.Duration = time.Minute
	// processRefreshInterval is how often the container of a running process
	// gets kept again, which restarts its exitedProcessTimeout. Doing it for
	// each of its lines would rewrite the entry for nothing.
	processRefreshInterval = time.Second
	// maxProcessItems bounds the containers kept per process.
	maxProcessItems uint64 = 16 * 1024
	// podSyncTimeout bounds the wait for the pods of the node at start.
	podSyncTimeout = 30 * time.Second
	// processStartSlack is how much later than its audit line a process may
	// seem to have started. Its start time is truncated to
	// util.ProcessStartTimeTick, and the audit timestamp comes from a coarse
	// clock.
	processStartSlack = time.Second
	// bootTimeWindow is how long a wall clock time of the boot is used at
	// least, see bootClock. It covers how long an audit line waits at most
	// until its process gets checked: the delay of reading the audit log and
	// backlogTimeout.
	bootTimeWindow = 5 * time.Minute
)

// errProcessStartedLater is returned by containerIDForProcess if the process
// with the PID started after the audit line got logged. The process of the
// line is gone and another one reused its PID.
var errProcessStartedLater = errors.New("process started after its audit line")

// containerLookup tells the container of the process of an audit line. The
// log and the JSON enricher share it.
type containerLookup struct {
	logger logr.Logger
	// containerIDCache holds the container of a process by its PID and start
	// time.
	containerIDCache *ttlcache.Cache[string, string]
	// processContainers maps the PIDs of processes seen running to their
	// container ID, for their lines read after they exited.
	processContainers *ttlcache.Cache[int, string]
	containers        *containerInfos
	boot              bootClock
}

// bootClock tells when the system booted on the wall clock, which converts
// the start time of a process, relative to the boot, to the wall clock of the
// audit timestamps. That is the current wall clock time minus the time since
// boot, which changes whenever the wall clock gets stepped or slewed. A later
// boot time makes a process seem to have started later, which drops its
// lines, so the earliest boot time seen within the last bootTimeWindow is
// used. That covers the time the audit lines checked now got logged at, which
// makes a change of the wall clock fail open:
//
//   - A forward step makes the boot time later. The earlier one is still used
//     for the lines logged before the step, so that the processes only seem
//     to have started earlier. Until the window passed, this accepts the line
//     of a process whose PID got reused within the size of the step.
//   - A backward step makes the boot time earlier, which gets used right
//     away. Lines logged before the step seem to have been logged later than
//     the processes started, which accepts them as well.
//
// Slewing moves the boot time slowly, the window keeps that from adding up.
// A line can still be dropped if the wall clock got stepped forward by more
// than processStartSlack after it got logged, and the line got checked more
// than bootTimeWindow later or was logged before the enricher started.
type bootClock struct {
	mu sync.Mutex
	// current and previous are the earliest boot times seen within the
	// current and the previous window, which started at windowStart.
	current, previous time.Time
	windowStart       time.Time
}

// get returns the earliest wall clock time of the boot seen within at least
// the last bootTimeWindow. It reports false if the time since boot is unknown.
func (b *bootClock) get(i impl) (time.Time, bool) {
	sinceBoot, err := i.Uptime()
	if err != nil || sinceBoot <= 0 {
		return time.Time{}, false
	}

	now := time.Now()
	// Without its monotonic reading, the boot time compares by the wall
	// clock with other boot times and with the audit timestamps.
	boot := now.Round(0).Add(-sinceBoot)

	b.mu.Lock()
	defer b.mu.Unlock()

	// The window is measured with the monotonic clock, which the wall clock
	// changes do not affect.
	if b.windowStart.IsZero() || now.Sub(b.windowStart) >= bootTimeWindow {
		b.previous, b.current, b.windowStart = b.current, boot, now
	}

	if boot.Before(b.current) {
		b.current = boot
	}

	if !b.previous.IsZero() && b.previous.Before(b.current) {
		return b.previous, true
	}

	return b.current, true
}

func newContainerLookup(logger logr.Logger) *containerLookup {
	return &containerLookup{
		logger: logger,
		containerIDCache: ttlcache.New(
			ttlcache.WithTTL[string, string](defaultCacheTimeout),
			ttlcache.WithCapacity[string, string](maxCacheItems),
		),
		processContainers: ttlcache.New(
			ttlcache.WithTTL[int, string](exitedProcessTimeout),
			ttlcache.WithCapacity[int, string](maxProcessItems),
			ttlcache.WithDisableTouchOnHit[int, string](),
		),
		containers: newContainerInfos(),
	}
}

// checkNodeName fails if the node the enricher runs on is unknown.
func checkNodeName(logger logr.Logger, nodeName string) error {
	if nodeName != "" {
		return nil
	}

	err := fmt.Errorf("%s environment variable not set", config.NodeNameEnvKey)
	logger.Error(err, "unable to run enricher")

	return err
}

// start watches the pods of the node until ctx is done, and expires the
// cached containers until the returned function gets called.
func (c *containerLookup) start(
	ctx context.Context, i impl, nodeName string,
) (stop func(), err error) {
	if err := c.containers.watch(ctx, i, nodeName); err != nil {
		return nil, err
	}

	c.waitForPods(ctx)

	c.logger.Info("Setting up caches", "expiry", defaultCacheTimeout)

	go c.containerIDCache.Start()
	go c.processContainers.Start()
	go c.containers.infoCache.Start()

	return func() {
		c.containerIDCache.Stop()
		c.processContainers.Stop()
		c.containers.infoCache.Stop()
	}, nil
}

// waitForPods waits until the pods of the node are known, so that the lines
// read right after the start get their container as well. It gives up after
// podSyncTimeout: an unreachable API server must not stop the enricher, and
// lines read before the pods are known look their container up again when
// they get emitted.
func (c *containerLookup) waitForPods(ctx context.Context) {
	syncCtx, cancel := context.WithTimeout(ctx, podSyncTimeout)
	defer cancel()

	if !cache.WaitForCacheSync(syncCtx.Done(), c.containers.pods.HasSynced) {
		c.logger.Info("Pods of the node are not known yet, continuing without them",
			"timeout", podSyncTimeout)
	}
}

// processGone reports whether the lookup of a process failed because it exited:
// its proc directory is gone, or reading a file of it fails with ESRCH if it
// exited after the file got opened.
func processGone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

// containerIDForProcess returns the container ID of the process which logged
// an audit line at eventTime. The container of a process which exited is the
// one it had when it was last seen running. A line can be read up to a minute
// after it got logged, so the process with the PID has to have started before
// eventTime, unless it is zero.
func (c *containerLookup) containerIDForProcess(
	i impl, pid int, eventTime time.Time,
) (string, error) {
	cID, started, err := i.ContainerIDForPID(c.containerIDCache, pid)
	if err == nil {
		err = c.startedBefore(i, pid, started, eventTime)
	}

	switch {
	case err == nil:
		c.keepProcessContainer(pid, cID)

		return cID, nil
	case processGone(err):
		if item := c.processContainers.Get(pid); item != nil {
			c.logger.V(config.VerboseLevel).Info(
				"Using the container of the exited process",
				"processID", pid, "containerID", item.Value(),
			)

			return item.Value(), nil
		}
	case errors.Is(err, util.ErrContainerIDNotFound):
		// A process outside of a container runs with the PID now.
		c.processContainers.Delete(pid)
	}

	return "", err
}

// startedBefore fails with errProcessStartedLater if the process with the PID,
// which started the duration started after the boot, started after eventTime.
// It skips the check if eventTime is zero or the time since boot is unknown.
func (c *containerLookup) startedBefore(
	i impl, pid int, started time.Duration, eventTime time.Time,
) error {
	if eventTime.IsZero() {
		return nil
	}

	boot, ok := c.boot.get(i)
	if !ok {
		return nil
	}

	if startedAt := boot.Add(started); startedAt.After(eventTime.Add(processStartSlack)) {
		return fmt.Errorf("%w: pid %d started at %s, the line got logged at %s",
			errProcessStartedLater, pid, startedAt.Format(time.RFC3339Nano),
			eventTime.Format(time.RFC3339Nano))
	}

	return nil
}

// auditTime returns when the audit line got logged, or the zero time if its
// timestamp cannot be parsed.
func auditTime(line *types.AuditLine) time.Time {
	t, err := common.AuditTime(line.TimestampID)
	if err != nil {
		return time.Time{}
	}

	return t
}

// keepProcessContainer keeps the container of a running process, unless it
// got kept within the refresh interval already.
func (c *containerLookup) keepProcessContainer(pid int, containerID string) {
	if item := c.processContainers.Get(pid); item != nil && item.Value() == containerID &&
		time.Until(item.ExpiresAt()) > exitedProcessTimeout-processRefreshInterval {
		return
	}

	c.processContainers.Set(pid, containerID, ttlcache.DefaultTTL)
}
