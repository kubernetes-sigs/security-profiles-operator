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
	"sync"
	"time"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// maxPodsPerContext bounds the pods remembered per SELinux context. More pods
// with the same context make it ambiguous anyway.
const maxPodsPerContext = 2

// selinuxContexts remembers the pods by the SELinux context of their AVCs,
// for the AVCs of processes which exited before they got looked up. Every pod
// whose AVCs resolve to one of its containers counts, so that a context which
// several pods use is ambiguous. An AVC is only attributed by its context if a
// single pod used it within defaultCacheTimeout, and that pod is recorded
// with a level the runtime assigned, which is unique per pod. A level the
// SELinux options set, like the per namespace levels of OpenShift, can be
// shared by other pods, and the kernel logs the denial of a permissive
// context only once, so a pod which logged no AVC may use the context as
// well.
type selinuxContexts struct {
	mu sync.Mutex
	// byContext holds per context the pods which used it, by their UID.
	byContext map[string]map[string]contextUse
}

// contextUse is the container of a pod which used a context last, and when.
type contextUse struct {
	info *types.ContainerInfo
	seen time.Time
	// attributable is set if the AVCs of exited processes with the context
	// may be recorded for the container, see selinuxContexts.
	attributable bool
}

func newSelinuxContexts() *selinuxContexts {
	return &selinuxContexts{byContext: map[string]map[string]contextUse{}}
}

// remember records that the container used the context at now. Up to
// maxCacheItems contexts are remembered.
func (c *selinuxContexts) remember(scontext string, info *types.ContainerInfo, now time.Time) {
	attributable := info.SelinuxRecordProfile != "" && !info.SelinuxLevelExplicit

	c.mu.Lock()
	defer c.mu.Unlock()

	pods, ok := c.byContext[scontext]
	if !ok {
		if len(c.byContext) >= int(maxCacheItems) {
			return
		}

		pods = map[string]contextUse{}
		c.byContext[scontext] = pods
	}

	// A further pod replaces the one which used the context longest ago, the
	// recent uses of the others keep the context ambiguous.
	if _, known := pods[info.PodUID]; !known && len(pods) >= maxPodsPerContext {
		oldest := ""

		for podUID, use := range pods {
			if oldest == "" || use.seen.Before(pods[oldest].seen) {
				oldest = podUID
			}
		}

		delete(pods, oldest)
	}

	pods[info.PodUID] = contextUse{info: info, seen: now, attributable: attributable}
}

// container returns the container of the single pod which used the context
// within defaultCacheTimeout before now, if its AVCs are attributable.
func (c *selinuxContexts) container(scontext string, now time.Time) (*types.ContainerInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var found *contextUse

	for _, use := range c.byContext[scontext] {
		if now.Sub(use.seen) >= defaultCacheTimeout {
			continue
		}

		if found != nil {
			return nil, false
		}

		found = &use
	}

	if found == nil || !found.attributable {
		return nil, false
	}

	return found.info, true
}

// sweep forgets the pods which are not on the node any more, and the uses
// older than defaultCacheTimeout.
func (c *selinuxContexts) sweep(present func(podUID string) bool, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for scontext, pods := range c.byContext {
		for podUID, use := range pods {
			if !present(podUID) || now.Sub(use.seen) >= defaultCacheTimeout {
				delete(pods, podUID)
			}
		}

		if len(pods) == 0 {
			delete(c.byContext, scontext)
		}
	}
}
