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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	apienricher "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	apimetrics "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/daemongrpc"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/auditsource"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// defaultCacheTimeout is the timeout for the container ID and info cache being
	// used. The chosen value is nothing more than a rough guess.
	defaultCacheTimeout time.Duration = time.Hour
	// auditBacklogMax is the number of lines kept per container.
	auditBacklogMax = 1024
	// auditBacklogDistinctMax is the number of lines kept per container
	// once auditBacklogMax is reached, as long as they differ from the lines
	// already kept by more than their timestamp and process. A container can
	// issue thousands of syscalls while it is looked up, mostly repeating
	// ones, and a recording misses every syscall which is only issued after
	// the backlog got full.
	auditBacklogDistinctMax = 4 * 1024
	// auditBacklogTotalMax is the number of lines kept across the backlogs
	// of all containers, which bounds the memory of the backlogs, as each one
	// of up to maxCacheItems containers could keep auditBacklogDistinctMax
	// lines otherwise.
	auditBacklogTotalMax = 64 * 1024

	// backlogTimeout is how long audit lines wait for the pod status to list
	// their container. The status is updated within seconds, so this only
	// needs to cover a slow API server.
	backlogTimeout time.Duration = time.Minute

	maxCacheItems uint64 = 1000

	// maxProfilesPerPod bounds the profiles recorded for the containers of a
	// pod at once, each of them records into one profile per kind. A pod
	// whose recording annotations change, which the info refresh picks up,
	// would take up every profile of the cache otherwise.
	maxProfilesPerPod = 32

	// uncollectedRecordingTimeout is how long the data recorded by the
	// containers of a pod which left the node is kept for the collection of
	// its profiles, like the one of the BPF recorder.
	uncollectedRecordingTimeout = time.Hour
	// sweepInterval is how often the data of pods which left the node gets
	// checked, see recordedData.sweep.
	sweepInterval = 5 * time.Minute

	// collectedProfileTimeout is how long the lines of a collected profile
	// get dropped. The audit log is read with a delay, and the lines can wait
	// in the backlog of their container for up to backlogTimeout.
	collectedProfileTimeout = defaultCacheTimeout
	// maxCollectedItems bounds the collected profiles which are remembered.
	maxCollectedItems uint64 = 16 * 1024
)

// recordedData holds what the log recorder recorded per profile, the
// syscalls or the AVCs, until the profile recorder collected it.
type recordedData struct {
	// mu makes collecting a profile atomic with recording for it.
	mu sync.Mutex
	// data holds the recordings themselves, not a cache of something
	// re-derivable: the recorder deletes each entry explicitly once it has
	// collected the profile. Expiring them on a timer silently truncates any
	// recording whose workload goes quiet for longer than the TTL, and the
	// recorder then sees "no syscalls" and writes no profile at all. It holds
	// up to maxCacheItems profiles, a new profile is refused while it is full
	// instead of evicting the recording of another one, see record. The
	// recordings of pods which left the node get dropped, see sweep.
	data *ttlcache.Cache[string, *recording]
	// goneSince holds since when the pods with recorded data are not on the
	// node any more, see sweep. Guarded by mu.
	goneSince map[string]time.Time
	// refused holds the profiles which got refused for a pod because the
	// cache was full, by profilePodKey, see record. They stay refused until
	// they get collected for the pod or no line came for them for
	// uncollectedRecordingTimeout: recording them once a slot frees up would
	// store a profile which misses everything before.
	refused *ttlcache.Cache[string, struct{}]
	// limitedPods holds the pods which hit maxProfilesPerPod, so that this
	// is told once per pod, see podLimited.
	limitedPods *ttlcache.Cache[string, struct{}]
	// collected holds per profile the containers whose recording got
	// collected. Their lines can be read after that, which would otherwise
	// record them again for nobody to collect. The lines of other containers,
	// like the ones of a pod which starts with the same profile after the
	// collection, are still recorded.
	collected *ttlcache.Cache[string, sets.Set[string]]
}

// recording is what got recorded for a profile, per container.
type recording struct {
	containers map[string]sets.Set[string]
	// pods holds the UID of the pod of each container.
	pods map[string]string
	// collecting holds per pod UID the containers whose data a collecting
	// get for the pod handed out, which a reset for the pod drops. A pod
	// without an entry had no collecting get.
	collecting map[string]sets.Set[string]
}

// containersOf returns the containers which recorded the profile for the pod
// with the UID, or all of them without a UID.
func (r *recording) containersOf(podUID string) sets.Set[string] {
	containers := sets.KeySet(r.containers)
	if podUID == "" {
		return containers
	}

	for containerID := range containers {
		if r.pods[containerID] != podUID {
			containers.Delete(containerID)
		}
	}

	return containers
}

func newRecordedData() *recordedData {
	return &recordedData{
		data: ttlcache.New(
			ttlcache.WithTTL[string, *recording](ttlcache.NoTTL),
		),
		goneSince: map[string]time.Time{},
		refused: ttlcache.New(
			ttlcache.WithTTL[string, struct{}](uncollectedRecordingTimeout),
			ttlcache.WithCapacity[string, struct{}](maxCollectedItems),
		),
		limitedPods: ttlcache.New(
			ttlcache.WithTTL[string, struct{}](uncollectedRecordingTimeout),
			ttlcache.WithCapacity[string, struct{}](maxCacheItems),
			ttlcache.WithDisableTouchOnHit[string, struct{}](),
		),
		collected: ttlcache.New(
			ttlcache.WithTTL[string, sets.Set[string]](collectedProfileTimeout),
			ttlcache.WithCapacity[string, sets.Set[string]](maxCollectedItems),
			ttlcache.WithDisableTouchOnHit[string, sets.Set[string]](),
		),
	}
}

// recordResult tells what record did with the items.
type recordResult int

const (
	// recorded means that the items got recorded.
	recorded recordResult = iota
	// alreadyCollected means that the recording of the container got
	// collected already.
	alreadyCollected
	// cacheFull means that maxCacheItems other profiles are recorded
	// already, the profile is refused until it gets collected.
	cacheFull
	// stillRefused means that the profile got refused before, see cacheFull.
	stillRefused
	// podLimited means that the pod has maxProfilesPerPod other profiles
	// recorded already, the profile is refused like for cacheFull. It is
	// only returned for the first refusal of the pod within
	// uncollectedRecordingTimeout, stillRefused afterwards.
	podLimited
)

// profilePodKey is the key of a profile of a pod in refused.
func profilePodKey(profile, podUID string) string {
	return profile + "\x00" + podUID
}

// record records the items of a container of the pod with the UID for the
// profile. Nothing is recorded if the recording of the container got
// collected already, or for a new profile while maxCacheItems profiles are
// recorded: evicting the recording of another profile would truncate a
// profile which is being recorded, and any pod can carry a recording
// annotation. A refused profile stays refused, see refused.
func (r *recordedData) record(
	profile, podUID, containerID string, items ...string,
) recordResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	if collected := r.collected.Get(profile); collected != nil &&
		collected.Value().Has(containerID) {
		return alreadyCollected
	}

	return r.recordLocked(profile, podUID, containerID, items...)
}

// recordSibling records the items like record, for a sibling of the
// container of the profile in the pod, see selinuxSiblingProfiles. The key
// of the sibling only tells it apart within the pod. The profile belongs to a
// single container of the pod, so nothing is recorded once any container of
// it got collected: nothing would collect the data of the sibling key until
// the pod left the node, see sweep.
func (r *recordedData) recordSibling(
	profile, podUID, siblingKey string, items ...string,
) recordResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	if collected := r.collected.Get(profile); collected != nil && collected.Value().Len() > 0 {
		return alreadyCollected
	}

	return r.recordLocked(profile, podUID, siblingKey, items...)
}

// recordLocked records the items, see record. It has to be called with mu
// held.
func (r *recordedData) recordLocked(
	profile, podUID, containerID string, items ...string,
) recordResult {
	// The lookup keeps a refused profile refused for as long as its lines
	// keep coming.
	if r.refused.Get(profilePodKey(profile, podUID)) != nil {
		return stillRefused
	}

	if r.data.Get(profile) == nil {
		if r.data.Len() >= int(maxCacheItems) {
			r.refused.Set(profilePodKey(profile, podUID), struct{}{}, ttlcache.DefaultTTL)

			return cacheFull
		}

		if r.profilesOfPodLocked(podUID) >= maxProfilesPerPod {
			r.refused.Set(profilePodKey(profile, podUID), struct{}{}, ttlcache.DefaultTTL)

			if r.limitedPods.Get(podUID) != nil {
				return stillRefused
			}

			r.limitedPods.Set(podUID, struct{}{}, ttlcache.DefaultTTL)

			return podLimited
		}
	}

	item, _ := r.data.GetOrSetFunc(profile, func() *recording {
		return &recording{
			containers: map[string]sets.Set[string]{},
			pods:       map[string]string{},
		}
	})

	rec := item.Value()

	containerItems, ok := rec.containers[containerID]
	if !ok {
		containerItems = sets.New[string]()
		rec.containers[containerID] = containerItems
		rec.pods[containerID] = podUID
	}

	containerItems.Insert(items...)

	return recorded
}

// profilesOfPodLocked returns the number of profiles recorded for the
// containers of the pod with the UID. It has to be called with mu held.
func (r *recordedData) profilesOfPodLocked(podUID string) int {
	count := 0

	for _, item := range r.data.Items() {
		for _, uid := range item.Value().pods {
			if uid == podUID {
				count++

				break
			}
		}
	}

	return count
}

// get returns what got recorded for the profile by the containers of the pod
// with the UID, or by every container without a UID. Any pod can carry the
// recording annotation of another one, its data is not part of the profile of
// the other pod. With collect, nothing gets recorded afterwards for the
// containers which recorded it, so that the returned data is all that reset
// drops. The data stays until then, so that a failed collection can be
// retried. Nothing is marked as collected if nothing got recorded.
func (r *recordedData) get(profile, podUID string, collect bool) (items []string, found bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	item := r.data.Get(profile)
	if item == nil {
		return nil, false
	}

	rec := item.Value()
	containers := rec.containersOf(podUID)

	if containers.Len() == 0 {
		return nil, false
	}

	merged := sets.New[string]()

	for containerID := range containers {
		merged = merged.Union(rec.containers[containerID])
	}

	if collect {
		if rec.collecting == nil {
			rec.collecting = map[string]sets.Set[string]{}
		}

		rec.collecting[podUID] = containers
		r.markCollected(profile, containers)
	}

	return merged.UnsortedList(), true
}

// reset drops what got recorded for the profile by the containers whose data
// the last collecting get for the pod with the UID handed out, or by all
// containers of the pod without one. Nothing gets recorded for these
// containers afterwards. The containers of other pods which carry the same
// recording annotation keep their data until their own pod gets collected, or
// left the node for uncollectedRecordingTimeout, see sweep.
func (r *recordedData) reset(profile, podUID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// The collection of a refused profile found nothing for the pod, a
	// later recording of the profile for it starts over. The refusals for
	// the other pods with the same annotation stay, their data is missing
	// as well.
	if podUID != "" {
		r.refused.Delete(profilePodKey(profile, podUID))
	} else {
		for key := range r.refused.Items() {
			if strings.HasPrefix(key, profilePodKey(profile, "")) {
				r.refused.Delete(key)
			}
		}
	}

	item := r.data.Get(profile)
	if item == nil {
		return
	}

	rec := item.Value()

	drop, ok := rec.collecting[podUID]
	if !ok {
		drop = rec.containersOf(podUID)
	}

	for containerID := range drop {
		delete(rec.containers, containerID)
		delete(rec.pods, containerID)
	}

	r.markCollected(profile, drop)

	delete(rec.collecting, podUID)

	// A container which started with the same profile while it got
	// collected keeps its recording.
	if len(rec.containers) == 0 {
		r.data.Delete(profile)
	}
}

// markCollected adds containers to the collected containers of the profile.
// It has to be called with mu held.
func (r *recordedData) markCollected(profile string, containers sets.Set[string]) {
	collected := containers.Clone()
	if item := r.collected.Get(profile); item != nil {
		collected = collected.Union(item.Value())
	}

	r.collected.Set(profile, collected, ttlcache.DefaultTTL)
}

// sweep drops what got recorded by the containers of pods which are not on
// the node since at least uncollectedRecordingTimeout, longer than the collection of their
// profiles gets retried. Their profiles did not get collected, like after a
// restart of the daemon, or the pods only carried a recording annotation
// which no recording asked for. present reports whether the pod with the UID
// is on the node. It returns the profiles whose data got dropped.
func (r *recordedData) sweep(present func(podUID string) bool, now time.Time) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	gone := map[string]time.Time{}
	dropped := []string{}

	for profile, item := range r.data.Items() {
		rec := item.Value()

		for containerID, podUID := range rec.pods {
			if present(podUID) {
				continue
			}

			since, ok := gone[podUID]
			if !ok {
				since, ok = r.goneSince[podUID]
				if !ok {
					since = now
				}

				gone[podUID] = since
			}

			if now.Sub(since) < uncollectedRecordingTimeout {
				continue
			}

			delete(rec.containers, containerID)
			delete(rec.pods, containerID)

			for uid, containers := range rec.collecting {
				containers.Delete(containerID)

				if containers.Len() == 0 {
					delete(rec.collecting, uid)
				}
			}
		}

		if len(rec.containers) == 0 {
			r.data.Delete(profile)

			dropped = append(dropped, profile)
		}
	}

	r.goneSince = gone

	return dropped
}

// start expires the collected profiles until stop gets called.
func (r *recordedData) start() {
	go r.data.Start()
	go r.collected.Start()
	go r.refused.Start()
	go r.limitedPods.Start()
}

func (r *recordedData) stop() {
	r.data.Stop()
	r.collected.Stop()
	r.refused.Stop()
	r.limitedPods.Stop()
}

type LogEnricherOptions struct {
	EnricherFiltersJson string
	AuditSource         string
}

var LogEnricherDefaultOptions = LogEnricherOptions{
	EnricherFiltersJson: "[]",
	AuditSource:         "Auditd",
}

// Enricher is the main structure of this package.
type Enricher struct {
	apienricher.UnimplementedEnricherServer
	impl
	source auditsource.AuditLineSource
	logger logr.Logger
	lookup *containerLookup
	// syscalls and avcs accumulate per recorded profile. They are normally
	// drained by the Reset* RPCs, but a recording that never completes (pod
	// force-deleted, recording removed) would otherwise keep its entry for the
	// lifetime of the daemon. They hold up to maxCacheItems profiles, a new
	// one is refused while they are full, and drop the data of pods which
	// left the node, see recordedData.
	syscalls       *recordedData
	avcs           *recordedData
	auditLineCache *ttlcache.Cache[string, *auditBacklog]
	// selinuxContexts holds the recorded pods by the SELinux context of
	// their AVCs, for the AVCs of processes which exited before their
	// container got looked up, see containerOfSelinuxContext.
	selinuxContexts *selinuxContexts
	enricherFilters []types.EnricherFilterOptions
	grpcServer      *grpc.Server
	metrics         *metrics.Sender[*apimetrics.AuditRequest]
	// nodeName is the node the enricher runs on, from the node name
	// environment variable.
	nodeName string
	// metricsBackoff is the retry backoff used when dialling the local metrics
	// server. It is a field so that tests do not have to spend the production
	// backoff as wall-clock time.
	metricsBackoff wait.Backoff
	// warned holds the per audit line warnings which got logged already,
	// which would otherwise be logged for every syscall.
	warned onceWarner
	// backlogLines counts the lines of the backlogs in auditLineCache.
	backlogLines atomic.Int64
	// budgetDropped counts the lines dropped because the backlogs of all
	// containers hold auditBacklogTotalMax lines.
	budgetDropped atomic.Uint64
	// serveErr gets the error of the GRPC server if it fails.
	serveErr <-chan error
}

// warnOnce logs msg at the default level the first time it is called with
// key, and at the verbose level afterwards, see onceWarner.
func (e *Enricher) warnOnce(key, msg string, kv ...any) {
	e.warned.warn(e.logger, key, msg, kv...)
}

// onceWarner logs a warning at the default level the first time it gets
// logged for a key, and at the verbose level afterwards. The keys are never
// forgotten, so they have to be bounded, for example by the architectures.
type onceWarner struct {
	keys sync.Map
}

func (w *onceWarner) warn(logger logr.Logger, key, msg string, kv ...any) {
	if _, warned := w.keys.LoadOrStore(key, struct{}{}); warned {
		logger.V(config.VerboseLevel).Info(msg, kv...)

		return
	}

	logger.Info(msg, kv...)
}

// unknownSyscallKey is the key of the warning about a syscall whose name is
// unknown. The syscall IDs of the audit lines are arbitrary numbers, so the
// warning is logged once per architecture only.
func unknownSyscallKey(arch string) string {
	return "syscall/" + archKey(arch)
}

// archKey returns the architecture as part of the key of a warning. The audit
// lines can carry any value, which must not grow the keys without bound, so
// the architectures which are not known share one key.
func archKey(arch string) string {
	if arch == "" || isKnownArch(arch) {
		return arch
	}

	return "unknown"
}

// New returns a new Enricher instance.
func New(logger logr.Logger, opts *LogEnricherOptions) (*Enricher, error) {
	actualOpts := LogEnricherDefaultOptions

	if opts != nil && opts.EnricherFiltersJson != "" {
		actualOpts.EnricherFiltersJson = opts.EnricherFiltersJson
	}

	enricherFilters, err := GetEnricherFilters(actualOpts.EnricherFiltersJson, logger)
	if err != nil {
		return nil, fmt.Errorf("get enricher filters: %w", err)
	}

	logger.Info("Enricher Filters", "filters", enricherFilters)

	var source auditsource.AuditLineSource

	if opts != nil && strings.EqualFold(opts.AuditSource, "bpf") {
		logger.Info("Using BPF-based audit source")

		//nolint:staticcheck,nolintlint // platform-dependent
		source, err = auditsource.NewBpfSource(logger)
		//nolint:staticcheck,nolintlint // platform-dependent
		if err != nil {
			return nil, err
		}
	} else {
		logger.Info("Using auditd-based audit source")
		source = auditsource.NewAuditdSource(logger)
	}

	e := &Enricher{
		impl:     newDefaultImpl(logger),
		source:   source,
		logger:   logger,
		lookup:   newContainerLookup(logger),
		syscalls: newRecordedData(),
		avcs:     newRecordedData(),
		auditLineCache: ttlcache.New(
			ttlcache.WithTTL[string, *auditBacklog](backlogTimeout),
			ttlcache.WithCapacity[string, *auditBacklog](maxCacheItems),
			// For the audit line cache we don't want to increase the TTL on
			// Get calls because we want the TTLs just to quietly expire
			// if/when the cache is full.
			ttlcache.WithDisableTouchOnHit[string, *auditBacklog](),
		),
		selinuxContexts: newSelinuxContexts(),
		enricherFilters: enricherFilters,
		// Read once, like the rest of the configuration.
		nodeName:       os.Getenv(config.NodeNameEnvKey),
		metricsBackoff: util.DefaultBackoff(),
	}

	e.auditLineCache.OnEviction(e.logDroppedBacklog)

	return e, nil
}

// logDroppedBacklog tells about a backlog which got dropped because its
// container did not show up in time or the cache is full. Its lines are
// missing from the recording, which is otherwise hard to explain. A backlog
// which got flushed after its container showed up is deleted, not dropped.
func (e *Enricher) logDroppedBacklog(
	_ context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[string, *auditBacklog],
) {
	item.Value().release()

	var why string

	switch reason {
	case ttlcache.EvictionReasonExpired:
		why = "the container did not show up in time"
	case ttlcache.EvictionReasonCapacityReached:
		why = "the backlog cache is full"
	case ttlcache.EvictionReasonDeleted, ttlcache.EvictionReasonMaxCostExceeded:
		// A flushed backlog gets deleted.
		return
	}

	kept, dropped := item.Value().size()

	// A container which is not managed by Kubernetes, like one of podman,
	// never shows up, its lines are no loss for the recordings. A pod of the
	// node may still report the container while one has pending containers,
	// see podindex.Index.MayShowUp.
	logger := e.logger
	if reason == ttlcache.EvictionReasonExpired && !e.lookup.containers.mayShowUp(item.Key()) {
		logger = e.logger.V(config.VerboseLevel)
		why = "no pod of the node has the container"
	}

	logger.Info(
		"Dropping the audit backlog of a container, its lines are missing from recordings",
		"containerID", item.Key(), "reason", why, "lines", kept, "droppedLines", dropped,
	)
}

// Run the log-enricher to scrap audit logs and enrich them with
// Kubernetes data (namespace, pod and container). It returns nil once ctx is
// done, after it stopped the audit source, the GRPC server, the metrics sender
// and the caches.
func (e *Enricher) Run(ctx context.Context) error {
	nodeName := e.nodeName
	if err := checkNodeName(e.logger, nodeName); err != nil {
		return err
	}

	e.logger.Info("Starting log-enricher on node", "node", nodeName)

	podsCtx, stopPods := context.WithCancel(ctx)
	defer stopPods()

	stopLookup, err := e.lookup.start(podsCtx, e.impl, nodeName)
	if err != nil {
		return err
	}
	defer stopLookup()

	go e.auditLineCache.Start()
	defer e.auditLineCache.Stop()

	e.syscalls.start()
	defer e.syscalls.stop()

	e.avcs.start()
	defer e.avcs.stop()

	sweep := time.NewTicker(sweepInterval)
	defer sweep.Stop()

	e.logger.Info("Connecting to local GRPC server")

	// The streams are bound to the context, so that stopping the sender
	// releases them as well.
	metricsCtx, stopMetrics := context.WithCancel(ctx)
	defer stopMetrics()

	// Connecting once up front lets a daemon which cannot reach the metrics
	// server at all fail early. The sender re-opens the stream on its own if it
	// breaks later on, and never blocks the audit loop below.
	e.metrics = metrics.NewContextSender(
		e.logger, metrics.DefaultSenderQueueSize, e.openMetricsStream,
	)
	if err := util.RetryWithBackoff(
		metricsCtx,
		e.metricsBackoff,
		func() error { return e.metrics.ConnectContext(metricsCtx) },
		func(error) bool { return true },
	); err != nil {
		return fmt.Errorf("connect to local GRPC server: %w", err)
	}

	go e.metrics.Run(metricsCtx)

	if err := e.startGrpcServer(ctx); err != nil {
		return fmt.Errorf("start GRPC server: %w", err)
	}
	defer func() {
		if e.grpcServer != nil {
			e.grpcServer.GracefulStop()
		}
	}()

	log, err := e.StartTail(e.source)
	if err != nil {
		return fmt.Errorf("tail audit log: %w", err)
	}
	defer e.source.Stop()

	// Taken before any container is looked up, see containerInfos.changed.
	changed := e.lookup.containers.changed()

	for {
		select {
		case <-ctx.Done():
			e.logger.Info("Stopping log-enricher", "reason", ctx.Err().Error())

			return nil
		case err := <-e.serveErr:
			return fmt.Errorf("run GRPC server: %w", err)
		case auditLine, ok := <-log:
			if !ok {
				err := e.TailErr(e.source)
				if err == nil {
					err = errTailEnded
				}

				return fmt.Errorf("enricher failed: %w", err)
			}

			e.processAuditLine(nodeName, auditLine)
		case <-changed:
			changed = e.lookup.containers.changed()

			// The pods may tell the containers of any of the backlogs now.
			e.dispatchListedBacklogs(nodeName)
		case <-sweep.C:
			e.sweepRecordings()
		}
	}
}

// processAuditLine dispatches an audit line, or keeps it in the backlog of its
// container until the container got looked up.
func (e *Enricher) processAuditLine(nodeName string, auditLine *types.AuditLine) {
	e.logger.V(config.VerboseLevel).
		Info("Get container ID for PID", "pid", auditLine.ProcessID)

	cID, err := e.lookup.containerIDForProcess(e.impl, auditLine.ProcessID, auditTime(auditLine))
	if err != nil {
		if info, ok := e.containerOfSelinuxContext(auditLine, err); ok {
			if err := e.dispatchAuditLine(nodeName, auditLine, info); err != nil {
				e.logger.Error(err, "dispatch audit line")
			}

			return
		}

		// Nothing is going to tell the container of this line later on:
		// the process is either gone without having been seen running or
		// runs outside of a container, and a later line with the same PID
		// may come from whatever process reused it.
		if processGone(err) || errors.Is(err, util.ErrContainerIDNotFound) ||
			errors.Is(err, errProcessStartedLater) {
			e.logger.V(config.VerboseLevel).Info(
				"Dropping audit line without container",
				"processID", auditLine.ProcessID, "reason", err.Error(),
			)
		} else {
			e.logger.Error(
				err, "unable to get container ID",
				"processID", auditLine.ProcessID,
			)
		}

		return
	}

	e.logger.V(config.VerboseLevel).Info("Get container info", "containerID", cID)

	info, err := e.lookup.containers.get(cID)
	if err != nil {
		e.logger.V(config.VerboseLevel).Info(
			"Container not known yet",
			"processID", auditLine.ProcessID,
			"containerID", cID,
			"reason", err.Error(),
		)

		// The pod status may just not list the container yet.
		if backlogErr := e.addToBacklog(cID, auditLine); backlogErr != nil {
			e.logger.Error(backlogErr, "adding line to backlog")
		}

		return
	}

	// check if there's anything in the cache for this container
	e.dispatchBacklog(nodeName, info)

	if err := e.dispatchAuditLine(nodeName, auditLine, info); err != nil {
		e.logger.Error(err, "dispatch audit line")
	}
}

// containerOfSelinuxContext returns the recorded container whose AVCs had the
// SELinux context of the AVC of a process which exited before it got looked
// up. Short lived processes, like the ones of a shell script, exit long
// before their lines are read, and the kernel does not log the denial of
// their context again once it got logged, so the AVC would be missing from
// the profile for good. The context of a recorded container carries the
// recording type and the level the runtime assigned to its pod, see
// selinuxContexts.
func (e *Enricher) containerOfSelinuxContext(
	auditLine *types.AuditLine, err error,
) (*types.ContainerInfo, bool) {
	if auditLine.AuditType != types.AuditTypeSelinux || auditLine.Scontext == "" ||
		!processGone(err) && !errors.Is(err, errProcessStartedLater) {
		return nil, false
	}

	remembered, ok := e.selinuxContexts.container(auditLine.Scontext, time.Now())
	if !ok {
		return nil, false
	}

	// The pod has to be still running: the runtime may assign the level of
	// a pod which is gone to another one. Its info gets read again like for
	// the lines of running processes, so that a removed recording annotation
	// counts.
	pods := e.lookup.containers.pods
	if pods == nil {
		return nil, false
	}

	pod, found := pods.Get(remembered.ContainerID)
	if !found || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return nil, false
	}

	info, infoErr := e.lookup.containers.get(remembered.ContainerID)
	if infoErr != nil || info.SelinuxRecordProfile == "" || info.SelinuxLevelExplicit {
		return nil, false
	}

	e.logger.V(config.VerboseLevel).Info(
		"Using the container of the SELinux context of the exited process",
		"processID", auditLine.ProcessID,
		"scontext", auditLine.Scontext,
		"containerID", info.ContainerID,
	)

	return info, true
}

// sweepRecordings drops the data recorded by the containers of pods which
// left the node uncollectedRecordingTimeout ago, see recordedData.sweep, and
// forgets the SELinux contexts of pods which left it. A pod which finished
// counts as gone: the late lines of a finished Job would keep its recording
// otherwise for as long as the pod object exists.
func (e *Enricher) sweepRecordings() {
	pods := e.lookup.containers.pods
	if pods == nil || !pods.HasSynced() {
		return
	}

	present := sets.New[string]()

	for _, pod := range pods.Pods() {
		if pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
			present.Insert(string(pod.UID))
		}
	}

	now := time.Now()

	e.selinuxContexts.sweep(present.Has, now)

	for name, recordedData := range map[string]*recordedData{
		"syscalls": e.syscalls,
		"avcs":     e.avcs,
	} {
		for _, profile := range recordedData.sweep(present.Has, now) {
			e.logger.Info("Dropping the uncollected recording of pods which left the node",
				"cache", name, "profile", profile)
		}
	}
}

// logRefused tells that a profile does not get recorded because the
// recordings of maxCacheItems other profiles are not collected yet, or its
// pod has maxProfilesPerPod other ones, once per refusal, see
// recordedData.record. Otherwise the recorder just reports "no syscalls
// found" and writes no profile, with nothing explaining why.
func (e *Enricher) logRefused(result recordResult, cache, profile string) {
	switch result {
	case cacheFull:
		e.logger.Info(
			"Not recording a profile because the cache is full: "+
				"the profile will not be recorded until the daemon collected it",
			"cache", cache, "profile", profile, "capacity", maxCacheItems,
		)
	case podLimited:
		e.logger.Info(
			"Not recording further profiles of a pod which has too many: "+
				"they will not be recorded until the daemon collected them",
			"cache", cache, "profile", profile, "limit", maxProfilesPerPod,
		)
	case recorded, alreadyCollected, stillRefused:
		e.logger.V(config.VerboseLevel).Info(
			"Not recording a refused profile", "cache", cache, "profile", profile,
		)
	}
}

// auditMetricsStream sends through the impl, so that tests can fake the
// stream.
type auditMetricsStream struct {
	e      *Enricher
	client apimetrics.Metrics_AuditIncClient
}

func (s auditMetricsStream) Send(req *apimetrics.AuditRequest) error {
	return s.e.SendMetric(s.client, req)
}

func (e *Enricher) openMetricsStream(
	ctx context.Context,
) (metrics.Stream[*apimetrics.AuditRequest], func(), error) {
	conn, err := e.Dial()
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to local GRPC server: %w", err)
	}

	release := func() {
		if err := e.Close(conn); err != nil {
			e.logger.Error(err, "Unable to close GRPC connection")
		}
	}

	client, err := e.AuditInc(ctx, apimetrics.NewMetricsClient(conn))
	if err != nil {
		release()

		return nil, nil, fmt.Errorf("create metrics audit client: %w", err)
	}

	return auditMetricsStream{e: e, client: client}, release, nil
}

// sendMetric queues a metric update. Enrichers without a metrics connection,
// like in tests of the dispatch functions, skip it.
func (e *Enricher) sendMetric(req *apimetrics.AuditRequest) {
	if e.metrics != nil {
		e.metrics.Send(req)
	}
}

func (e *Enricher) startGrpcServer(ctx context.Context) error {
	e.logger.Info("Starting GRPC server API")

	if _, err := e.Stat(config.GRPCServerSocketEnricher); err == nil {
		if err := e.RemoveAll(config.GRPCServerSocketEnricher); err != nil {
			return fmt.Errorf("remove GRPC socket file: %w", err)
		}
	}

	listener, err := e.Listen(ctx, "unix", config.GRPCServerSocketEnricher)
	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}

	if err := e.Chown(
		config.GRPCServerSocketEnricher,
		config.UserRootless,
		config.UserRootless,
	); err != nil {
		return errors.Join(
			fmt.Errorf("change GRPC socket owner to rootless: %w", err),
			listener.Close(),
		)
	}

	e.grpcServer = grpc.NewServer(daemongrpc.ServerOptions()...)
	apienricher.RegisterEnricherServer(e.grpcServer, e)

	e.serveErr = daemongrpc.Serve(func() error { return e.Serve(e.grpcServer, listener) })

	return nil
}

// Dial can be used to connect to the default GRPC server by creating a new
// client.
func Dial() (*grpc.ClientConn, error) {
	return daemongrpc.Dial(config.GRPCServerSocketEnricher)
}

// auditBacklog holds the lines of a container until it got looked up.
type auditBacklog struct {
	mu    sync.Mutex
	lines []*types.AuditLine
	// seen holds the lines without their timestamp and process.
	seen map[types.AuditLine]struct{}
	// dropped counts the lines which did not fit.
	dropped uint64
	// total counts the lines kept by all backlogs, see auditBacklogTotalMax.
	total *atomic.Int64
	// released is set once the backlog left the cache, see release.
	released bool
}

// newAuditBacklog returns an empty backlog whose lines count towards total.
func newAuditBacklog(total *atomic.Int64) *auditBacklog {
	return &auditBacklog{seen: map[types.AuditLine]struct{}{}, total: total}
}

// release takes the lines of the backlog out of the total, once it left the
// cache. Lines added afterwards are dropped, nobody would dispatch them.
func (b *auditBacklog) release() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.released {
		return
	}

	b.released = true
	b.total.Add(-int64(len(b.lines)))
}

// size returns the number of kept and dropped lines.
func (b *auditBacklog) size() (kept int, dropped uint64) {
	if b == nil {
		return 0, 0
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	return len(b.lines), b.dropped
}

// add keeps the line, unless the backlog is full. Once auditBacklogMax is
// reached, only lines which differ from the kept ones by more than their
// timestamp and process are kept, so that forking workloads do not fill it
// up with the same syscalls. It returns the number of dropped lines, and
// whether the line got dropped because all backlogs together are full.
func (b *auditBacklog) add(line *types.AuditLine) (kept bool, dropped uint64, overBudget bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := *line
	key.TimestampID = ""
	key.ProcessID = 0
	// Pointers compare by address, and the recording does not use them.
	key.Uid = nil
	key.Gid = nil

	if len(b.lines) >= auditBacklogMax {
		if _, ok := b.seen[key]; ok || len(b.lines) >= auditBacklogDistinctMax {
			b.dropped++

			return false, b.dropped, false
		}
	}

	if b.released {
		b.dropped++

		return false, b.dropped, false
	}

	if b.total.Load() >= auditBacklogTotalMax {
		b.dropped++

		return false, b.dropped, true
	}

	b.total.Add(1)

	// The strings of the line may point into the whole record it got parsed
	// from, which must not be kept alive with the line.
	b.lines = append(b.lines, cloneAuditLine(line))
	b.seen[*cloneAuditLine(&key)] = struct{}{}

	return true, b.dropped, false
}

// cloneAuditLine returns a copy of the line with its own strings.
func cloneAuditLine(line *types.AuditLine) *types.AuditLine {
	c := *line
	c.AuditType = strings.Clone(c.AuditType)
	c.TimestampID = strings.Clone(c.TimestampID)
	c.Executable = strings.Clone(c.Executable)
	c.Arch = strings.Clone(c.Arch)
	c.Scontext = strings.Clone(c.Scontext)
	c.Tcontext = strings.Clone(c.Tcontext)
	c.Tclass = strings.Clone(c.Tclass)
	c.Perm = strings.Clone(c.Perm)
	c.Apparmor = strings.Clone(c.Apparmor)
	c.Operation = strings.Clone(c.Operation)
	c.Profile = strings.Clone(c.Profile)
	c.Name = strings.Clone(c.Name)
	c.ExtraInfo = strings.Clone(c.ExtraInfo)

	return &c
}

// snapshot returns the kept lines and the number of dropped ones.
func (b *auditBacklog) snapshot() (lines []*types.AuditLine, dropped uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return slices.Clone(b.lines), b.dropped
}

// addToBacklog keeps a line until the pod status lists its container. The
// backlog is kept per container, so that a process reusing the PID in another
// container never gets the lines of the previous one.
func (e *Enricher) addToBacklog(containerID string, line *types.AuditLine) error {
	var backlog *auditBacklog

	item := e.auditLineCache.Get(containerID)
	if item != nil {
		backlog = item.Value()
		if backlog == nil {
			// this should not happen, but let's be paranoid
			return errors.New("nil backlog in cache")
		}
	} else {
		// Get hides a backlog which expired but was not cleaned up yet, and
		// Set would overwrite it without an eviction. Evicting the expired
		// ones logs that their lines got dropped, see logDroppedBacklog.
		e.auditLineCache.DeleteExpired()

		backlog = newAuditBacklog(&e.backlogLines)
	}

	// If the backlog is full, we just stop adding new lines. The backlog gets
	// flushed into the recording once the container shows up, or dropped with
	// a log line once its TTL expires.
	kept, dropped, overBudget := backlog.add(line)
	if !kept {
		// A backlog which did not fit is not cached, so its count would
		// start over with every line.
		if overBudget {
			if total := e.budgetDropped.Add(1); total%auditBacklogMax == 1 {
				e.logger.Info(
					"Audit backlogs of all containers are full, dropping lines",
					"limit", auditBacklogTotalMax, "droppedLines", total,
				)
			}

			return nil
		}

		if dropped%auditBacklogMax == 1 {
			e.logger.Info(
				"Audit backlog of container is full, dropping lines",
				"containerID", containerID, "droppedLines", dropped,
			)
		}

		return nil
	}

	// A cached backlog got the line in place. Setting it again would restart
	// its TTL, which counts from its first line.
	if item == nil {
		e.auditLineCache.Set(containerID, backlog, ttlcache.DefaultTTL)
	}

	return nil
}

// dispatchBacklog sends the backlogged lines of every process of the
// container, now that its info is known. Lines of processes which stay idle
// would otherwise expire, together with what the container did first.
func (e *Enricher) dispatchBacklog(nodeName string, info *types.ContainerInfo) {
	item, found := e.auditLineCache.GetAndDelete(info.ContainerID)
	if !found || item == nil {
		return
	}

	// The eviction callback releases the backlog as well, but only later
	// on, which would drop the lines right after a flush.
	item.Value().release()

	lines, _ := item.Value().snapshot()

	for _, auditLine := range lines {
		if err := e.dispatchAuditLine(nodeName, auditLine, info); err != nil {
			e.logger.Error(err, "dispatch audit line")
		}
	}
}

// dispatchListedBacklogs sends the backlogged lines of the containers the pods
// of the node tell now. Otherwise they would wait for another line of their
// container, which may never come for a container whose processes exited.
func (e *Enricher) dispatchListedBacklogs(nodeName string) {
	for _, containerID := range e.auditLineCache.Keys() {
		if info, err := e.lookup.containers.get(containerID); err == nil {
			e.dispatchBacklog(nodeName, info)
		}
	}
}

func (e *Enricher) dispatchAuditLine(
	nodeName string,
	auditLine *types.AuditLine,
	info *types.ContainerInfo,
) error {
	switch auditLine.AuditType {
	case types.AuditTypeSelinux:
		e.dispatchSelinuxLine(nodeName, auditLine, info)
	case types.AuditTypeSeccomp:
		e.dispatchSeccompLine(nodeName, auditLine, info)
	case types.AuditTypeApparmor:
		e.dispatchApparmorLine(nodeName, auditLine, info)
	default:
		return fmt.Errorf("unknown audit line type %s", auditLine.AuditType)
	}

	return nil
}

// logLevelFor resolves the configured filters for a log record given as logr
// key/value pairs. The pairs are what the logger wants, so the map the filters
// need is only materialised when filters are actually configured; building one
// per audit line otherwise costs an allocation and 11 map inserts for nothing.
func (e *Enricher) logLevelFor(kv []any) types.EnricherLogLevel {
	if len(e.enricherFilters) == 0 {
		return types.EnricherLogLevelMetadata
	}

	logMap := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			continue
		}

		logMap[key] = kv[i+1]
	}

	return ApplyEnricherFilters(logMap, e.enricherFilters)
}

func (e *Enricher) dispatchSelinuxLine(
	nodeName string,
	auditLine *types.AuditLine,
	info *types.ContainerInfo,
) {
	kv := []any{
		"timestamp", auditLine.TimestampID,
		"type", auditLine.AuditType,
		"profile", info.SelinuxRecordProfile,
		"node", nodeName,
		"namespace", info.Namespace,
		"pod", info.PodName,
		"container", info.ContainerName,
		"perm", auditLine.Perm,
		"scontext", auditLine.Scontext,
		"tcontext", auditLine.Tcontext,
		"tclass", auditLine.Tclass,
	}

	logLevel := e.logLevelFor(kv)
	if logLevel == types.EnricherLogLevelNone {
		e.logger.V(config.VerboseLevel).Info("Skip logging", kv...)
	} else {
		e.logger.Info("audit", kv...)

		e.sendMetric(&apimetrics.AuditRequest{
			Node:      nodeName,
			Namespace: info.Namespace,
			Pod:       info.PodName,
			Container: info.ContainerName,
			SelinuxReq: &apimetrics.AuditRequest_SelinuxAuditReq{
				Scontext: auditLine.Scontext,
				Tcontext: auditLine.Tcontext,
			},
		})
	}

	// Every pod which uses the context counts, see selinuxContexts.
	if auditLine.Scontext != "" {
		e.selinuxContexts.remember(auditLine.Scontext, info, time.Now())
	}

	if info.SelinuxRecordProfile == "" {
		return
	}

	avcs := []string{}

	for perm := range strings.SplitSeq(auditLine.Perm, " ") {
		avc := &apienricher.AvcResponse_SelinuxAvc{
			Perm:     perm,
			Scontext: auditLine.Scontext,
			Tcontext: auditLine.Tcontext,
			Tclass:   auditLine.Tclass,
		}

		jsonBytes, err := protojson.Marshal(avc)
		if err != nil {
			// An empty entry would fail the Avcs RPC of the recording.
			e.logger.Error(err, "marshall protobuf")

			continue
		}

		avcs = append(avcs, string(jsonBytes))
	}

	if len(avcs) == 0 {
		return
	}

	e.recordAvcs(info.SelinuxRecordProfile, info.PodUID, info.ContainerID, avcs)

	e.recordSiblingAvcs(info, avcs)
}

// recordSiblingAvcs records the AVCs for the other containers of the pod
// with the same context, which do not log the denial again, see
// selinuxSiblingProfiles. A sibling which cannot run any more, like an init
// container which finished, does not need them. That is decided by the
// current pod, the siblings of the info are older. Their own ID is not known
// before they start, the key only has to tell them apart within the pod.
func (e *Enricher) recordSiblingAvcs(info *types.ContainerInfo, avcs []string) {
	if len(info.SelinuxSiblingProfiles) == 0 || e.lookup.containers.pods == nil {
		return
	}

	pod, found := e.lookup.containers.pods.Get(info.ContainerID)
	if !found {
		return
	}

	for name, profile := range info.SelinuxSiblingProfiles {
		if !containerMayRun(pod, name, info.ContainerName) {
			continue
		}

		e.logRecordedAvcs(
			e.avcs.recordSibling(profile, info.PodUID, "pod/"+info.PodUID+"/"+name, avcs...),
			profile,
		)
	}
}

// recordAvcs records the AVCs for the profile, see recordedData.record.
func (e *Enricher) recordAvcs(profile, podUID, containerID string, avcs []string) {
	e.logRecordedAvcs(e.avcs.record(profile, podUID, containerID, avcs...), profile)
}

// logRecordedAvcs logs the AVCs which did not get recorded for the profile.
func (e *Enricher) logRecordedAvcs(result recordResult, profile string) {
	switch result {
	case recorded:
	case alreadyCollected:
		e.logger.V(config.VerboseLevel).
			Info("Dropping AVC of a collected profile", "profile", profile)
	case cacheFull, stillRefused, podLimited:
		e.logRefused(result, "avcs", profile)
	}
}

func (e *Enricher) dispatchSeccompLine(
	nodeName string,
	auditLine *types.AuditLine,
	info *types.ContainerInfo,
) {
	syscallName, err := syscallName(auditLine.SystemCallID, auditLine.Arch)
	if err != nil {
		e.warnOnce(
			unknownSyscallKey(auditLine.Arch),
			"no syscall name found for ID",
			"syscallID", auditLine.SystemCallID,
			"arch", auditLine.Arch,
			"error", err.Error(),
		)

		return
	}

	kv := []any{
		"timestamp", auditLine.TimestampID,
		"type", auditLine.AuditType,
		"node", nodeName,
		"namespace", info.Namespace,
		"pod", info.PodName,
		"container", info.ContainerName,
		"executable", auditLine.Executable,
		"pid", auditLine.ProcessID,
		"syscallID", auditLine.SystemCallID,
		"syscallName", syscallName,
	}

	if auditLine.Arch != "" {
		kv = append(kv, "arch", auditLine.Arch)
	}

	logLevel := e.logLevelFor(kv)
	if logLevel == types.EnricherLogLevelNone {
		e.logger.V(config.VerboseLevel).Info("Skip logging", kv...)
	} else {
		e.logger.Info("audit", kv...)

		e.sendMetric(&apimetrics.AuditRequest{
			Node:      nodeName,
			Namespace: info.Namespace,
			Pod:       info.PodName,
			Container: info.ContainerName,
			SeccompReq: &apimetrics.AuditRequest_SeccompAuditReq{
				Syscall: syscallName,
			},
		})
	}

	// A recorded profile only covers the native architecture, the syscall
	// would not be allowed by adding its name.
	if info.SeccompRecordProfile != "" && !isNativeArch(auditLine.Arch) {
		// Keyed by the architecture only, the keys of the profiles would
		// grow without bound on a long running node.
		e.warnOnce(
			"arch/"+archKey(auditLine.Arch),
			"Not recording syscalls of a non-native architecture",
			"profile", info.SeccompRecordProfile,
			"syscallName", syscallName,
			"arch", auditLine.Arch,
		)

		return
	}

	if info.SeccompRecordProfile == "" {
		return
	}

	switch result := e.syscalls.record(
		info.SeccompRecordProfile, info.PodUID, info.ContainerID, syscallName,
	); result {
	case recorded:
	case alreadyCollected:
		e.logger.V(config.VerboseLevel).Info(
			"Dropping syscall of a collected profile", "profile", info.SeccompRecordProfile,
		)
	case cacheFull, stillRefused, podLimited:
		e.logRefused(result, "syscalls", info.SeccompRecordProfile)
	}
}

func (e *Enricher) dispatchApparmorLine(
	nodeName string,
	auditLine *types.AuditLine,
	info *types.ContainerInfo,
) {
	kv := []any{
		"timestamp", auditLine.TimestampID,
		"type", auditLine.AuditType,
		"node", nodeName,
		"namespace", info.Namespace,
		"pod", info.PodName,
		"container", info.ContainerName,
		"executable", auditLine.Executable,
		"pid", auditLine.ProcessID,
		"apparmor", auditLine.Apparmor,
		"operation", auditLine.Operation,
		"profile", auditLine.Profile,
		"name", auditLine.Name,
	}

	if auditLine.ExtraInfo != "" {
		kv = append(kv, "extra_info", auditLine.ExtraInfo)
	}

	logLevel := e.logLevelFor(kv)
	if logLevel == types.EnricherLogLevelNone {
		e.logger.V(config.VerboseLevel).Info("Skip logging", kv...)

		return
	}

	e.logger.Info("audit", kv...)

	e.sendMetric(&apimetrics.AuditRequest{
		Node:      nodeName,
		Namespace: info.Namespace,
		Pod:       info.PodName,
		Container: info.ContainerName,
		ApparmorReq: &apimetrics.AuditRequest_ApparmorAuditReq{
			Profile:   auditLine.Profile,
			Operation: auditLine.Operation,
			Apparmor:  auditLine.Apparmor,
		},
	})
}
