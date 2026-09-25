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
	"k8s.io/client-go/kubernetes"

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

	// backlogTimeout is how long audit lines wait for the pod status to list
	// their container. The status is updated within seconds, so this only
	// needs to cover a slow API server.
	backlogTimeout time.Duration = time.Minute

	// exitedProcessTimeout is how long the container of a process is kept
	// for the audit lines read after the process exited. The audit log is
	// read with a delay, so a short lived process is often gone before its
	// lines are processed. The container is only used while no process with
	// the PID exists, so another process could get lines of a gone one only
	// if it reused the PID and exited again within this time.
	exitedProcessTimeout time.Duration = time.Minute
	// maxProcessItems bounds the containers kept per process.
	maxProcessItems uint64 = 16 * 1024

	defaultTimeout time.Duration = time.Minute
	maxMsgSize     int           = 16 * 1024 * 1024
	maxCacheItems  uint64        = 1000
)

type syncSet struct {
	mu  sync.RWMutex
	set sets.Set[string]
}

func newSyncSet() *syncSet {
	return &syncSet{set: sets.New[string]()}
}

func (s *syncSet) Insert(items ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.set.Insert(items...)
}

func (s *syncSet) UnsortedList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.set.UnsortedList()
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
	source           auditsource.AuditLineSource
	logger           logr.Logger
	containerIDCache *ttlcache.Cache[string, string]
	// processContainers maps the PIDs of processes seen running to their
	// container ID, for their lines read after they exited.
	processContainers *ttlcache.Cache[int, string]
	infoCache         *ttlcache.Cache[string, *types.ContainerInfo]
	// missingContainers remembers the containers recently not found in the
	// pod list.
	missingContainers *ttlcache.Cache[string, struct{}]
	// syscalls and avcs accumulate per recorded profile. They are normally
	// drained by the Reset* RPCs, but a recording that never completes (pod
	// force-deleted, recording removed) would otherwise keep its entry for the
	// lifetime of the daemon, so they are bounded like every other cache here.
	syscalls        *ttlcache.Cache[string, *syncSet]
	avcs            *ttlcache.Cache[string, *syncSet]
	auditLineCache  *ttlcache.Cache[string, []*types.AuditLine]
	clientset       kubernetes.Interface
	enricherFilters []types.EnricherFilterOptions
	grpcServer      *grpc.Server
	metrics         *metrics.Sender[*apimetrics.AuditRequest]
	// nodeName defaults to the value of the node name environment variable.
	nodeName string
	// metricsBackoff is the retry backoff used when dialling the local metrics
	// server. It is a field so that tests do not have to spend the production
	// backoff as wall-clock time.
	metricsBackoff wait.Backoff
	// containerBackoff is the retry backoff for container lookups, a field for
	// the same reason as metricsBackoff.
	containerBackoff wait.Backoff
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
		impl:   newDefaultImpl(logger),
		source: source,
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
		infoCache: ttlcache.New(
			ttlcache.WithTTL[string, *types.ContainerInfo](defaultCacheTimeout),
			ttlcache.WithCapacity[string, *types.ContainerInfo](maxCacheItems),
		),
		missingContainers: newMissingContainerCache(),
		// The syscall and AVC sets are the recording itself, not a cache of
		// something re-derivable: the recorder deletes each entry explicitly
		// once it has collected the profile (grpc.go Syscalls/Avcs reset).
		// Expiring them on a timer silently truncates any recording whose
		// workload goes quiet for longer than the TTL, and the recorder then
		// sees "no syscalls" and writes no profile at all.
		syscalls: ttlcache.New(
			ttlcache.WithTTL[string, *syncSet](ttlcache.NoTTL),
			ttlcache.WithCapacity[string, *syncSet](maxCacheItems),
		),
		avcs: ttlcache.New(
			ttlcache.WithTTL[string, *syncSet](ttlcache.NoTTL),
			ttlcache.WithCapacity[string, *syncSet](maxCacheItems),
		),
		auditLineCache: ttlcache.New(
			ttlcache.WithTTL[string, []*types.AuditLine](backlogTimeout),
			ttlcache.WithCapacity[string, []*types.AuditLine](maxCacheItems),
			// For the audit line cache we don't want to increase the TTL on
			// Get calls because we want the TTLs just to quietly expire
			// if/when the cache is full.
			ttlcache.WithDisableTouchOnHit[string, []*types.AuditLine](),
		),
		enricherFilters:  enricherFilters,
		metricsBackoff:   util.DefaultBackoff(),
		containerBackoff: defaultContainerBackoff(),
	}

	// Say plainly when a recording is dropped for capacity. Otherwise the
	// recorder just reports "no syscalls found" and writes no profile, with
	// nothing explaining why.
	for name, cache := range map[string]*ttlcache.Cache[string, *syncSet]{
		"syscalls": e.syscalls,
		"avcs":     e.avcs,
	} {
		cache.OnEviction(func(
			_ context.Context, reason ttlcache.EvictionReason,
			item *ttlcache.Item[string, *syncSet],
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
// Kubernetes data (namespace, pod and container).
func (e *Enricher) Run() error {
	clusterConfig, err := e.InClusterConfig()
	if err != nil {
		return fmt.Errorf("get in-cluster config: %w", err)
	}

	e.clientset, err = e.NewForConfig(clusterConfig)
	if err != nil {
		return fmt.Errorf("load in-cluster config: %w", err)
	}

	e.logger.Info("Setting up caches", "expiry", defaultCacheTimeout)

	go e.containerIDCache.Start()
	defer e.containerIDCache.Stop()

	go e.processContainers.Start()
	defer e.processContainers.Stop()

	go e.infoCache.Start()
	defer e.infoCache.Stop()

	go e.missingContainers.Start()
	defer e.missingContainers.Stop()

	go e.auditLineCache.Start()
	defer e.auditLineCache.Stop()

	go e.syscalls.Start()
	defer e.syscalls.Stop()

	go e.avcs.Start()
	defer e.avcs.Stop()

	if e.nodeName == "" {
		e.nodeName = os.Getenv(config.NodeNameEnvKey)
	}

	nodeName := e.nodeName
	if nodeName == "" {
		err := fmt.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		e.logger.Error(err, "unable to run enricher")

		return err
	}

	e.logger.Info("Starting log-enricher on node", "node", nodeName)

	e.logger.Info("Connecting to local GRPC server")

	// Connecting once up front lets a daemon which cannot reach the metrics
	// server at all fail early. The sender re-opens the stream on its own if it
	// breaks later on, and never blocks the audit loop below.
	e.metrics = metrics.NewSender(e.logger, metrics.DefaultSenderQueueSize, e.openMetricsStream)
	if err := util.RetryEx(
		&e.metricsBackoff,
		e.metrics.Connect,
		func(error) bool { return true },
	); err != nil {
		return fmt.Errorf("connect to local GRPC server: %w", err)
	}

	metricsCtx, stopMetrics := context.WithCancel(context.Background())
	defer stopMetrics()

	go e.metrics.Run(metricsCtx)

	if err := e.startGrpcServer(); err != nil {
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

	containers := &containerLookup{
		nodeName:  nodeName,
		clientSet: e.clientset,
		impl:      e.impl,
		infoCache: e.infoCache,
		missing:   e.missingContainers,
		logger:    e.logger,
		backoff:   e.containerBackoff,
	}

	for auditLine := range log {
		e.logger.V(config.VerboseLevel).
			Info("Get container ID for PID", "pid", auditLine.ProcessID)

		cID, err := e.containerIDForProcess(auditLine.ProcessID)
		if err != nil {
			// Nothing is going to tell the container of this line later on:
			// the process is either gone without having been seen running or
			// runs outside of a container, and a later line with the same PID
			// may come from whatever process reused it.
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, util.ErrContainerIDNotFound) {
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

			continue
		}

		e.logger.V(config.VerboseLevel).Info("Get container info", "containerID", cID)

		listings := containers.listings

		info, err := containers.getContainerInfo(context.Background(), cID)
		if containers.listings != listings {
			e.dispatchListedBacklogs(nodeName)
		}

		if err != nil {
			e.logger.Error(
				err, "container ID not found in cluster",
				"processID", auditLine.ProcessID,
				"containerID", cID,
			)

			// The pod status may just not list the container yet.
			if backlogErr := e.addToBacklog(cID, auditLine); backlogErr != nil {
				e.logger.Error(backlogErr, "adding line to backlog")
			}

			continue
		}

		// check if there's anything in the cache for this container
		e.dispatchBacklog(nodeName, info)

		err = e.dispatchAuditLine(nodeName, auditLine, info)
		if err != nil {
			e.logger.Error(
				err, "dispatch audit line")

			continue
		}
	}

	return fmt.Errorf("enricher failed: %w", e.source.TailErr())
}

// containerIDForProcess returns the container ID of a process. The container
// of a process which exited is the one it had when it was last seen running.
func (e *Enricher) containerIDForProcess(pid int) (string, error) {
	cID, err := e.ContainerIDForPID(e.containerIDCache, pid)

	switch {
	case err == nil:
		e.processContainers.Set(pid, cID, ttlcache.DefaultTTL)

		return cID, nil
	case errors.Is(err, os.ErrNotExist):
		if item := e.processContainers.Get(pid); item != nil {
			e.logger.V(config.VerboseLevel).Info(
				"Using the container of the exited process",
				"processID", pid, "containerID", item.Value(),
			)

			return item.Value(), nil
		}
	case errors.Is(err, util.ErrContainerIDNotFound):
		// A process outside of a container runs with the PID now.
		e.processContainers.Delete(pid)
	}

	return "", err
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

func (e *Enricher) openMetricsStream() (metrics.Stream[*apimetrics.AuditRequest], func(), error) {
	conn, err := e.Dial()
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to local GRPC server: %w", err)
	}

	release := func() {
		if err := e.Close(conn); err != nil {
			e.logger.Error(err, "Unable to close GRPC connection")
		}
	}

	client, err := e.AuditInc(apimetrics.NewMetricsClient(conn))
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

func (e *Enricher) startGrpcServer() error {
	e.logger.Info("Starting GRPC server API")

	if _, err := e.Stat(config.GRPCServerSocketEnricher); err == nil {
		if err := e.RemoveAll(config.GRPCServerSocketEnricher); err != nil {
			return fmt.Errorf("remove GRPC socket file: %w", err)
		}
	}

	listener, err := e.Listen("unix", config.GRPCServerSocketEnricher)
	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}

	if err := e.Chown(
		config.GRPCServerSocketEnricher,
		config.UserRootless,
		config.UserRootless,
	); err != nil {
		return fmt.Errorf("change GRPC socket owner to rootless: %w", err)
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

// addToBacklog keeps a line until the pod status lists its container. The
// backlog is kept per container, so that a process reusing the PID in another
// container never gets the lines of the previous one.
func (e *Enricher) addToBacklog(containerID string, line *types.AuditLine) error {
	item := e.auditLineCache.Get(containerID)
	if item == nil {
		e.auditLineCache.Set(containerID, []*types.AuditLine{line}, ttlcache.DefaultTTL)

		return nil
	}

	auditBacklog := item.Value()

	if auditBacklog == nil {
		// this should not happen, but let's be paranoid
		return errors.New("nil slice in cache")
	}

	// If the number of backlog messages per container is over the limit, we
	// just stop adding new ones. Eventually the TTL will expire and the
	// backlog will flush. In case the workload appears later, we create a
	// partial policy but that was true before this change anyway
	if len(auditBacklog) > auditBacklogMax {
		return nil
	}

	e.auditLineCache.Set(containerID, append(auditBacklog, line), ttlcache.DefaultTTL)

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

	for _, auditLine := range item.Value() {
		if err := e.dispatchAuditLine(nodeName, auditLine, info); err != nil {
			e.logger.Error(err, "dispatch audit line")
		}
	}
}

// dispatchListedBacklogs sends the backlogged lines of the containers the pod
// list has now. Otherwise they would wait for another line of their container,
// which may never come for a container whose processes exited.
func (e *Enricher) dispatchListedBacklogs(nodeName string) {
	for _, containerID := range e.auditLineCache.Keys() {
		if item := e.infoCache.Get(containerID); item != nil {
			e.dispatchBacklog(nodeName, item.Value())
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
		"profile", info.RecordProfile,
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

	if info.RecordProfile != "" {
		for perm := range strings.SplitSeq(auditLine.Perm, " ") {
			avc := &apienricher.AvcResponse_SelinuxAvc{
				Perm:     perm,
				Scontext: auditLine.Scontext,
				Tcontext: auditLine.Tcontext,
				Tclass:   auditLine.Tclass,
			}

			jsonBytes, err := protojson.Marshal(avc)
			if err != nil {
				e.logger.Error(err, "marshall protobuf")
			}

			item, _ := e.avcs.GetOrSetFunc(info.RecordProfile, newSyncSet)
			if item != nil {
				item.Value().Insert(string(jsonBytes))
			}
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
		e.logger.Info(
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
	if info.RecordProfile != "" && !isNativeArch(auditLine.Arch) {
		e.logger.Info(
			"Not recording syscall of a non-native architecture",
			"profile", info.RecordProfile, "syscallName", syscallName, "arch", auditLine.Arch,
		)

		return
	}

	if info.RecordProfile != "" {
		item, _ := e.syscalls.GetOrSetFunc(info.RecordProfile, newSyncSet)
		if item != nil {
			item.Value().Insert(syscallName)
		}
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
