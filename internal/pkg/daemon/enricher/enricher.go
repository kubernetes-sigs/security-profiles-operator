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
	"strconv"
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
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// defaultCacheTimeout is the timeout for the container ID and info cache being
	// used. The chosen value is nothing more than a rough guess.
	defaultCacheTimeout time.Duration = time.Hour
	auditBacklogMax                   = 128

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
	infoCache        *ttlcache.Cache[string, *types.ContainerInfo]
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
		infoCache: ttlcache.New(
			ttlcache.WithTTL[string, *types.ContainerInfo](defaultCacheTimeout),
			ttlcache.WithCapacity[string, *types.ContainerInfo](maxCacheItems),
		),
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
			ttlcache.WithTTL[string, []*types.AuditLine](defaultCacheTimeout),
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

	go e.infoCache.Start()
	defer e.infoCache.Stop()

	go e.auditLineCache.Start()
	defer e.auditLineCache.Stop()

	go e.syscalls.Start()
	defer e.syscalls.Stop()

	go e.avcs.Start()
	defer e.avcs.Stop()

	nodeName := e.Getenv(config.NodeNameEnvKey)
	if nodeName == "" {
		err := fmt.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		e.logger.Error(err, "unable to run enricher")

		return err
	}

	e.logger.Info("Starting log-enricher on node", "node", nodeName)

	e.logger.Info("Connecting to local GRPC server")

	var (
		conn          *grpc.ClientConn
		metricsClient apimetrics.Metrics_AuditIncClient
	)

	if err := util.RetryEx(&e.metricsBackoff, func() (err error) {
		conn, err = e.Dial()
		if err != nil {
			return fmt.Errorf("connecting to local GRPC server: %w", err)
		}

		client := apimetrics.NewMetricsClient(conn)

		metricsClient, err = e.AuditInc(client)
		if err != nil {
			e.Close(conn)

			return fmt.Errorf("create metrics audit client: %w", err)
		}

		return nil
	}, func(err error) bool { return true }); err != nil {
		return fmt.Errorf("connect to local GRPC server: %w", err)
	}

	defer e.Close(conn)

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

	for auditLine := range log {
		e.logger.V(config.VerboseLevel).
			Info("Get container ID for PID", "pid", auditLine.ProcessID)

		cID, err := e.ContainerIDForPID(e.containerIDCache, auditLine.ProcessID)
		if errors.Is(err, os.ErrNotExist) {
			// We're probably in container creation or removal
			if backlogErr := e.addToBacklog(auditLine); backlogErr != nil {
				e.logger.Error(backlogErr, "adding line to backlog")
			}

			continue
		}

		if err != nil {
			e.logger.Error(
				err, "unable to get container ID",
				"processID", auditLine.ProcessID,
			)

			if backlogErr := e.addToBacklog(auditLine); backlogErr != nil {
				e.logger.Error(backlogErr, "adding line to backlog")
			}

			continue
		}

		e.logger.V(config.VerboseLevel).Info("Get container info", "containerID", cID)

		info, err := getContainerInfo(context.Background(),
			nodeName, cID, e.clientset, e.impl, e.infoCache, e.logger, e.containerBackoff)
		if err != nil {
			e.logger.Error(
				err, "container ID not found in cluster",
				"processID", auditLine.ProcessID,
				"containerID", cID,
			)

			if backlogErr := e.addToBacklog(auditLine); backlogErr != nil {
				e.logger.Error(backlogErr, "adding line to backlog")
			}

			continue
		}

		// check if there's anything in the cache for this processID
		e.dispatchBacklog(metricsClient, nodeName, info, auditLine.ProcessID)

		err = e.dispatchAuditLine(metricsClient, nodeName, auditLine, info)
		if err != nil {
			e.logger.Error(
				err, "dispatch audit line")

			continue
		}
	}

	return fmt.Errorf("enricher failed: %w", e.source.TailErr())
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

func (e *Enricher) addToBacklog(line *types.AuditLine) error {
	strPid := strconv.Itoa(line.ProcessID)

	item := e.auditLineCache.Get(strPid)
	if item == nil {
		e.AddToBacklog(e.auditLineCache, strPid, []*types.AuditLine{line})

		return nil
	}

	auditBacklog := item.Value()

	if auditBacklog == nil {
		// this should not happen, but let's be paranoid
		return errors.New("nil slice in cache")
	}

	// If the number of backlog messages per process is over the limit, we just stop
	// adding new ones. Eventually the TTL will expire and the backlog will flush.
	// In case the workload appears later, we create a partial policy but that was
	// true before this change anyway
	if len(auditBacklog) > auditBacklogMax {
		return nil
	}

	e.AddToBacklog(e.auditLineCache, strPid, append(auditBacklog, line))

	return nil
}

func (e *Enricher) dispatchBacklog(
	metricsClient apimetrics.Metrics_AuditIncClient,
	nodeName string,
	info *types.ContainerInfo,
	processID int,
) {
	strPid := strconv.Itoa(processID)

	auditBacklog := e.GetFromBacklog(e.auditLineCache, strPid)
	for _, auditLine := range auditBacklog {
		if err := e.dispatchAuditLine(metricsClient, nodeName, auditLine, info); err != nil {
			e.logger.Error(
				err, "dispatch audit line")

			continue
		}
	}

	e.FlushBacklog(e.auditLineCache, strPid)
}

func (e *Enricher) dispatchAuditLine(
	metricsClient apimetrics.Metrics_AuditIncClient,
	nodeName string,
	auditLine *types.AuditLine,
	info *types.ContainerInfo,
) error {
	switch auditLine.AuditType {
	case types.AuditTypeSelinux:
		e.dispatchSelinuxLine(metricsClient, nodeName, auditLine, info)
	case types.AuditTypeSeccomp:
		e.dispatchSeccompLine(metricsClient, nodeName, auditLine, info)
	case types.AuditTypeApparmor:
		e.dispatchApparmorLine(metricsClient, nodeName, auditLine, info)
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
	metricsClient apimetrics.Metrics_AuditIncClient,
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

		if err := e.SendMetric(
			metricsClient,
			&apimetrics.AuditRequest{
				Node:       nodeName,
				Namespace:  info.Namespace,
				Pod:        info.PodName,
				Container:  info.ContainerName,
				Executable: auditLine.Executable,
				SelinuxReq: &apimetrics.AuditRequest_SelinuxAuditReq{
					Scontext: auditLine.Scontext,
					Tcontext: auditLine.Tcontext,
				},
			},
		); err != nil {
			e.logger.Error(err, "unable to update metrics")
		}
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
	metricsClient apimetrics.Metrics_AuditIncClient,
	nodeName string,
	auditLine *types.AuditLine,
	info *types.ContainerInfo,
) {
	syscallName, err := syscallName(auditLine.SystemCallID)
	if err != nil {
		e.logger.Info(
			"no syscall name found for ID",
			"syscallID", auditLine.SystemCallID,
			"err", err.Error(),
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

	logLevel := e.logLevelFor(kv)
	if logLevel == types.EnricherLogLevelNone {
		e.logger.V(config.VerboseLevel).Info("Skip logging", kv...)
	} else {
		e.logger.Info("audit", kv...)

		if err := e.SendMetric(
			metricsClient,
			&apimetrics.AuditRequest{
				Node:       nodeName,
				Namespace:  info.Namespace,
				Pod:        info.PodName,
				Container:  info.ContainerName,
				Executable: auditLine.Executable,
				SeccompReq: &apimetrics.AuditRequest_SeccompAuditReq{
					Syscall: syscallName,
				},
			},
		); err != nil {
			e.logger.Error(err, "unable to update metrics")
		}
	}

	if info.RecordProfile != "" {
		item, _ := e.syscalls.GetOrSetFunc(info.RecordProfile, newSyncSet)
		if item != nil {
			item.Value().Insert(syscallName)
		}
	}
}

func (e *Enricher) dispatchApparmorLine(
	metricsClient apimetrics.Metrics_AuditIncClient,
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
		e.logger.V(1).Info("skip logging", kv...)

		return
	}

	e.logger.Info("audit", kv...)

	if err := e.SendMetric(
		metricsClient,
		&apimetrics.AuditRequest{
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
		},
	); err != nil {
		e.logger.Error(err, "unable to update the metrics")
	}
}
