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
	"slices"
	"time"

	"github.com/jellydator/ttlcache/v3"
	v1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

var errNoContainerInfo = errors.New("no pod of the node has the container")

// The pods of the node run in every namespace, so the access is cluster scoped.
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// containerInfos tells the pod of a container, from the watched pods of the
// node. The info of a container is kept after its pod got deleted, for the
// audit lines which are read after the container exited.
type containerInfos struct {
	// pods is nil until the enricher runs.
	pods      *podindex.Index
	infoCache *ttlcache.Cache[string, *cachedInfo]
	// now returns the current time, a field so that tests can move it.
	now func() time.Time
}

// cachedInfo is the info of a container and when it got read from its pod.
type cachedInfo struct {
	info *types.ContainerInfo
	read time.Time
}

// infoRefreshInterval is how long the cached info of a container is used
// before it gets read from its pod again. A recording annotation stripped from
// a running pod would be used for as long as the container logs lines
// otherwise.
const infoRefreshInterval = time.Minute

func newContainerInfos() *containerInfos {
	return &containerInfos{
		infoCache: ttlcache.New(
			ttlcache.WithTTL[string, *cachedInfo](defaultCacheTimeout),
			ttlcache.WithCapacity[string, *cachedInfo](maxCacheItems),
		),
		now: time.Now,
	}
}

// watch starts watching the pods of the node until ctx is done.
func (c *containerInfos) watch(ctx context.Context, i impl, nodeName string) error {
	clusterConfig, err := i.InClusterConfig()
	if err != nil {
		return fmt.Errorf("get in-cluster config: %w", err)
	}

	clientset, err := i.NewForConfig(clusterConfig)
	if err != nil {
		return fmt.Errorf("load in-cluster config: %w", err)
	}

	pods, err := podindex.New(i.PodListerWatcher(clientset, nodeName))
	if err != nil {
		return fmt.Errorf("watch pods of node %s: %w", nodeName, err)
	}

	c.pods = pods

	go pods.Run(ctx)

	return nil
}

// get returns the info of the container, without waiting for its pod to
// report it. A cached info gets read from the pod again after
// infoRefreshInterval, and is used as it is once the pod is gone, for the
// lines read after the container exited.
func (c *containerInfos) get(containerID string) (*types.ContainerInfo, error) {
	var cached *cachedInfo

	if item := c.infoCache.Get(containerID); item != nil {
		cached = item.Value()

		if c.now().Sub(cached.read) < infoRefreshInterval {
			return cached.info, nil
		}
	}

	var (
		pod *v1.Pod
		ok  bool
	)

	if c.pods != nil {
		pod, ok = c.pods.Get(containerID)
	}

	if !ok {
		if cached != nil {
			// The pod is gone, which the lines of the next
			// infoRefreshInterval do not look up again.
			c.infoCache.Set(
				containerID, &cachedInfo{info: cached.info, read: c.now()}, ttlcache.DefaultTTL,
			)

			return cached.info, nil
		}

		return nil, errNoContainerInfo
	}

	info := containerInfoOf(pod, containerID)
	c.infoCache.Set(containerID, &cachedInfo{info: info, read: c.now()}, ttlcache.DefaultTTL)

	return info, nil
}

// mayShowUp reports whether a pod of the node has the container, or may still
// report it, see podindex.Index.MayShowUp. Every container may show up until
// the enricher runs.
func (c *containerInfos) mayShowUp(containerID string) bool {
	if c.pods == nil {
		return true
	}

	return c.pods.MayShowUp(containerID)
}

// changed returns a channel which is closed once a pod of the node got added
// or updated. Take it before calling get, so that no change in between is
// missed.
func (c *containerInfos) changed() <-chan struct{} {
	if c.pods == nil {
		// Never closed.
		return nil
	}

	return c.pods.Changed()
}

// containerInfoOf returns the info of the container with the ID in the pod.
func containerInfoOf(pod *v1.Pod, containerID string) *types.ContainerInfo {
	containerName, _ := podindex.ContainerName(pod, containerID)

	info := &types.ContainerInfo{
		PodName:       pod.Name,
		PodUID:        string(pod.UID),
		ContainerName: containerName,
		Namespace:     pod.Namespace,
		ContainerID:   containerID,
		SeccompRecordProfile: recordProfile(
			pod, config.SeccompProfileRecordLogsAnnotationKey, containerName,
		),
		SelinuxRecordProfile: recordProfile(
			pod, config.SelinuxProfileRecordLogsAnnotationKey, containerName,
		),
	}

	// The SELinux options only matter for the AVCs of a recorded container.
	if info.SelinuxRecordProfile == "" {
		return info
	}

	if options, found := selinuxOptionsOf(pod, containerName); found {
		info.SelinuxLevelExplicit = options.Level != ""
		info.SelinuxSiblingProfiles = selinuxSiblingProfiles(pod, containerName, options)
	}

	return info
}

// selinuxOptionsOf returns the effective SELinux options of the container.
func selinuxOptionsOf(pod *v1.Pod, containerName string) (v1.SELinuxOptions, bool) {
	for container := range util.AllContainers(pod) {
		if container.Name == containerName {
			return effectiveSELinuxOptions(pod, container.SecurityContext), true
		}
	}

	return v1.SELinuxOptions{}, false
}

// selinuxSiblingProfiles returns by container name the profiles the log
// recorder records the other containers of the pod for, which run with the
// SELinux options of the container. They share the SELinux context: the
// runtime assigns the level per pod, unless the options set one. In a
// permissive domain the kernel logs a denial only once per context, after
// that it allows the access without a log line. An init container which reads
// a file keeps the main container from logging the same read, so the AVCs of
// one of these containers are recorded for all of them.
func selinuxSiblingProfiles(
	pod *v1.Pod, containerName string, options v1.SELinuxOptions,
) map[string]string {
	var siblings map[string]string

	for container := range util.AllContainers(pod) {
		if container.Name == containerName ||
			effectiveSELinuxOptions(pod, container.SecurityContext) != options {
			continue
		}

		profile := recordProfile(pod, config.SelinuxProfileRecordLogsAnnotationKey, container.Name)
		if profile == "" {
			continue
		}

		if siblings == nil {
			siblings = map[string]string{}
		}

		siblings[container.Name] = profile
	}

	return siblings
}

// containerMayRun reports whether the container of the pod with the name
// runs, or may still start or restart, while the container named running
// runs. A container which terminated does not run again if it is an init
// container which succeeded, unless it is a sidecar, or if the pod does not
// restart it. An init container which is not a sidecar does not run any more
// once a regular container runs, even if the status of the pod does not tell
// yet that it terminated.
func containerMayRun(pod *v1.Pod, name, running string) bool {
	if pod.Status.Phase == v1.PodSucceeded || pod.Status.Phase == v1.PodFailed {
		return false
	}

	for i := range pod.Spec.InitContainers {
		container := &pod.Spec.InitContainers[i]
		if container.Name != name {
			continue
		}

		sidecar := container.RestartPolicy != nil &&
			*container.RestartPolicy == v1.ContainerRestartPolicyAlways
		if !sidecar && slices.ContainsFunc(pod.Spec.Containers, func(c v1.Container) bool {
			return c.Name == running
		}) {
			return false
		}

		terminated := terminatedState(pod.Status.InitContainerStatuses, name)

		// A sidecar restarts whatever the policy of the pod, a failed init
		// container unless the pod never restarts its containers.
		return terminated == nil || sidecar ||
			terminated.ExitCode != 0 && pod.Spec.RestartPolicy != v1.RestartPolicyNever
	}

	statuses := slices.Concat(pod.Status.ContainerStatuses, pod.Status.EphemeralContainerStatuses)

	terminated := terminatedState(statuses, name)
	if terminated == nil {
		return true
	}

	switch pod.Spec.RestartPolicy {
	case v1.RestartPolicyNever:
		return false
	case v1.RestartPolicyOnFailure:
		return terminated.ExitCode != 0
	case v1.RestartPolicyAlways:
		return true
	default:
		return true
	}
}

// terminatedState returns the state of the container with the name if it
// terminated.
func terminatedState(statuses []v1.ContainerStatus, name string) *v1.ContainerStateTerminated {
	for i := range statuses {
		if statuses[i].Name == name {
			return statuses[i].State.Terminated
		}
	}

	return nil
}

// effectiveSELinuxOptions returns the SELinux options the container runs
// with: the ones of the pod, which the ones of the container override field
// by field.
func effectiveSELinuxOptions(pod *v1.Pod, securityContext *v1.SecurityContext) v1.SELinuxOptions {
	var options v1.SELinuxOptions

	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SELinuxOptions != nil {
		options = *pod.Spec.SecurityContext.SELinuxOptions
	}

	if securityContext == nil || securityContext.SELinuxOptions == nil {
		return options
	}

	own := securityContext.SELinuxOptions

	for _, field := range []struct{ value, override *string }{
		{&options.User, &own.User},
		{&options.Role, &own.Role},
		{&options.Type, &own.Type},
		{&options.Level, &own.Level},
	} {
		if *field.override != "" {
			*field.value = *field.override
		}
	}

	return options
}

// recordProfile returns the profile of the recording annotation of the
// container with the key prefix. A value which names another container did
// not come from the recording webhook, and the container does not get
// recorded into the profile of the other one, see
// util.RecordingAnnotationValueContainer.
func recordProfile(pod *v1.Pod, prefix, containerName string) string {
	profile := pod.Annotations[prefix+containerName]

	if named, ok := util.RecordingAnnotationValueContainer(profile); !ok || named != containerName {
		return ""
	}

	return profile
}
