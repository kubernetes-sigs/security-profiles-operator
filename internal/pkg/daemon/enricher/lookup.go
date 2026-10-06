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
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"k8s.io/client-go/tools/cache"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
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
)

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

// containerIDForProcess returns the container ID of a process. The container
// of a process which exited is the one it had when it was last seen running.
func (c *containerLookup) containerIDForProcess(i impl, pid int) (string, error) {
	cID, err := i.ContainerIDForPID(c.containerIDCache, pid)

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

// keepProcessContainer keeps the container of a running process, unless it
// got kept within the refresh interval already.
func (c *containerLookup) keepProcessContainer(pid int, containerID string) {
	if item := c.processContainers.Get(pid); item != nil && item.Value() == containerID &&
		time.Until(item.ExpiresAt()) > exitedProcessTimeout-processRefreshInterval {
		return
	}

	c.processContainers.Set(pid, containerID, ttlcache.DefaultTTL)
}
