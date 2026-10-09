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
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	apienricher "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	apimetrics "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
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

	// backlogTimeout is how long audit lines wait for the pod status to list
	// their container. The status is updated within seconds, so this only
	// needs to cover a slow API server.
	backlogTimeout time.Duration = time.Minute

	defaultTimeout time.Duration = time.Minute
	maxMsgSize     int           = 16 * 1024 * 1024
	maxCacheItems  uint64        = 1000

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
	// recorder then sees "no syscalls" and writes no profile at all.
	data *ttlcache.Cache[string, *recording]
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
	// collecting holds the containers whose data a collecting get handed
	// out, which reset drops. It is nil if no collecting get happened.
	collecting sets.Set[string]
}

func newRecordedData() *recordedData {
	return &recordedData{
		data: ttlcache.New(
			ttlcache.WithTTL[string, *recording](ttlcache.NoTTL),
			ttlcache.WithCapacity[string, *recording](maxCacheItems),
		),
		collected: ttlcache.New(
			ttlcache.WithTTL[string, sets.Set[string]](collectedProfileTimeout),
			ttlcache.WithCapacity[string, sets.Set[string]](maxCollectedItems),
			ttlcache.WithDisableTouchOnHit[string, sets.Set[string]](),
		),
	}
}

// insert records the items of a container for the profile. It reports false
// if the recording of the container got collected already, then nothing is
// recorded.
func (r *recordedData) insert(profile, containerID string, items ...string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if collected := r.collected.Get(profile); collected != nil &&
		collected.Value().Has(containerID) {
		return false
	}

	item, _ := r.data.GetOrSetFunc(profile, func() *recording {
		return &recording{containers: map[string]sets.Set[string]{}}
	})

	rec := item.Value()

	recorded, ok := rec.containers[containerID]
	if !ok {
		recorded = sets.New[string]()
		rec.containers[containerID] = recorded
	}

	recorded.Insert(items...)

	return true
}

// get returns what got recorded for the profile. With collect, nothing gets
// recorded afterwards for the containers which recorded it, so that the
// returned data is all that reset drops. The data stays until then, so that a
// failed collection can be retried. Nothing is marked as collected if nothing
// got recorded.
func (r *recordedData) get(profile string, collect bool) (items []string, found bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	item := r.data.Get(profile)
	if item == nil {
		return nil, false
	}

	rec := item.Value()
	merged := sets.New[string]()

	for _, recorded := range rec.containers {
		merged = merged.Union(recorded)
	}

	if collect {
		rec.collecting = sets.KeySet(rec.containers)
		r.markCollected(profile, rec.collecting)
	}

	return merged.UnsortedList(), true
}

// reset drops what got recorded for the profile by the containers whose data
// the last collecting get handed out, or by all of them without one. Nothing
// gets recorded for these containers afterwards.
func (r *recordedData) reset(profile string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	item := r.data.Get(profile)
	if item == nil {
		return
	}

	rec := item.Value()

	drop := rec.collecting
	if drop == nil {
		drop = sets.KeySet(rec.containers)
	}

	for containerID := range drop {
		delete(rec.containers, containerID)
	}

	r.markCollected(profile, drop)

	rec.collecting = nil

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

// start expires the collected profiles until stop gets called.
func (r *recordedData) start() {
	go r.data.Start()
	go r.collected.Start()
}

func (r *recordedData) stop() {
	r.data.Stop()
	r.collected.Stop()
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
	// lifetime of the daemon, so they are bounded like every other cache here.
	syscalls        *recordedData
	avcs            *recordedData
	auditLineCache  *ttlcache.Cache[string, *auditBacklog]
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
	// warned holds the keys of the per audit line warnings which got logged
	// already, which would otherwise be logged for every syscall. The keys
	// are bounded by the architectures and syscall numbers.
	warned sync.Map
}

// warnOnce logs msg at the default level the first time it is called with
// key, and at the verbose level afterwards.
func (e *Enricher) warnOnce(key, msg string, kv ...any) {
	if _, warned := e.warned.LoadOrStore(key, struct{}{}); warned {
		e.logger.V(config.VerboseLevel).Info(msg, kv...)

		return
	}

	e.logger.Info(msg, kv...)
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
		enricherFilters: enricherFilters,
		// Read once, like the rest of the configuration.
		nodeName:       os.Getenv(config.NodeNameEnvKey),
		metricsBackoff: util.DefaultBackoff(),
	}

	// Say plainly when a recording is dropped for capacity. Otherwise the
	// recorder just reports "no syscalls found" and writes no profile, with
	// nothing explaining why.
	for name, recorded := range map[string]*recordedData{
		"syscalls": e.syscalls,
		"avcs":     e.avcs,
	} {
		recorded.data.OnEviction(func(
			_ context.Context, reason ttlcache.EvictionReason,
			item *ttlcache.Item[string, *recording],
		) {
			if reason != ttlcache.EvictionReasonCapacityReached {
				return
			}

			logger.Info(
				"Dropping a recording because the cache is full: "+
					"the profile will be recorded incomplete or not at all",
				"cache", name, "profile", item.Key(), "capacity", maxCacheItems,
			)
		})
	}

	return e, nil
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

	e.grpcServer = grpc.NewServer(
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.MaxRecvMsgSize(maxMsgSize),
	)
	apienricher.RegisterEnricherServer(e.grpcServer, e)

	go func() {
		if err := e.Serve(e.grpcServer, listener); err != nil {
			e.logger.Error(err, "unable to run GRPC server")
		}
	}()

	return nil
}

// Dial can be used to connect to the default GRPC server by creating a new
// client.
func Dial() (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		"unix://"+config.GRPCServerSocketEnricher,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("GRPC dial: %w", err)
	}

	return conn, nil
}

// auditBacklog holds the lines of a container until it got looked up.
type auditBacklog struct {
	mu    sync.Mutex
	lines []*types.AuditLine
	// seen holds the lines without their timestamp and process.
	seen map[types.AuditLine]struct{}
	// dropped counts the lines which did not fit.
	dropped uint64
}

// add keeps the line, unless the backlog is full. Once auditBacklogMax is
// reached, only lines which differ from the kept ones by more than their
// timestamp and process are kept, so that forking workloads do not fill it
// up with the same syscalls. It returns the number of dropped lines.
func (b *auditBacklog) add(line *types.AuditLine) (kept bool, dropped uint64) {
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

			return false, b.dropped
		}
	}

	b.lines = append(b.lines, line)
	b.seen[key] = struct{}{}

	return true, b.dropped
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
		backlog = &auditBacklog{seen: map[types.AuditLine]struct{}{}}
	}

	// If the backlog is full, we just stop adding new lines. Eventually the
	// TTL will expire and the backlog will flush. In case the workload
	// appears later, we create a partial policy.
	kept, dropped := backlog.add(line)
	if !kept {
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
			Node:       nodeName,
			Namespace:  info.Namespace,
			Pod:        info.PodName,
			Container:  info.ContainerName,
			Executable: auditLine.Executable,
			SelinuxReq: &apimetrics.AuditRequest_SelinuxAuditReq{
				Scontext: auditLine.Scontext,
				Tcontext: auditLine.Tcontext,
			},
		})
	}

	if info.SelinuxRecordProfile != "" {
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

		if len(avcs) > 0 && !e.avcs.insert(info.SelinuxRecordProfile, info.ContainerID, avcs...) {
			e.logger.V(config.VerboseLevel).Info(
				"Dropping AVC of a collected profile", "profile", info.SelinuxRecordProfile,
			)
		}
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
			fmt.Sprintf("syscall/%s/%d", auditLine.Arch, auditLine.SystemCallID),
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
			Node:       nodeName,
			Namespace:  info.Namespace,
			Pod:        info.PodName,
			Container:  info.ContainerName,
			Executable: auditLine.Executable,
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
			"arch/"+auditLine.Arch,
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

	if !e.syscalls.insert(info.SeccompRecordProfile, info.ContainerID, syscallName) {
		e.logger.V(config.VerboseLevel).Info(
			"Dropping syscall of a collected profile", "profile", info.SeccompRecordProfile,
		)
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
		Node:       nodeName,
		Namespace:  info.Namespace,
		Pod:        info.PodName,
		Container:  info.ContainerName,
		Executable: auditLine.Executable,
		ApparmorReq: &apimetrics.AuditRequest_ApparmorAuditReq{
			Profile:   auditLine.Profile,
			Operation: auditLine.Operation,
			Apparmor:  auditLine.Apparmor,
			Name:      auditLine.Name,
		},
	})
}
