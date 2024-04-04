/*
Copyright 2020 The Kubernetes Authors.

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
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"github.com/nxadm/tail"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	rutil "sigs.k8s.io/release-utils/util"

	apienricher "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	apimetrics "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
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

// Enricher is the main structure of this package.
type Enricher struct {
	apienricher.UnimplementedEnricherServer
	impl
	logger           logr.Logger
	containerIDCache *ttlcache.Cache[string, string]
	infoCache        *ttlcache.Cache[string, *types.ContainerInfo]
	syscalls         sync.Map
	avcs             sync.Map
	auditLineCache   *ttlcache.Cache[string, []*types.AuditLine]
	clientset        kubernetes.Interface
}

// New returns a new Enricher instance.
func New(logger logr.Logger) *Enricher {
	return &Enricher{
		impl:   &defaultImpl{},
		logger: logger,
		containerIDCache: ttlcache.New(
			ttlcache.WithTTL[string, string](defaultCacheTimeout),
			ttlcache.WithCapacity[string, string](maxCacheItems),
		),
		infoCache: ttlcache.New(
			ttlcache.WithTTL[string, *types.ContainerInfo](defaultCacheTimeout),
			ttlcache.WithCapacity[string, *types.ContainerInfo](maxCacheItems),
		),
		syscalls: sync.Map{},
		avcs:     sync.Map{},
		auditLineCache: ttlcache.New(
			ttlcache.WithTTL[string, []*types.AuditLine](defaultCacheTimeout),
			ttlcache.WithCapacity[string, []*types.AuditLine](maxCacheItems),
			// For the audit line cache we don't want to increase the TTL on
			// Get calls because we want the TTLs just to quietly expire
			// if/when the cache is full.
			ttlcache.WithDisableTouchOnHit[string, []*types.AuditLine](),
		),
	}
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

	e.logger.Info(fmt.Sprintf("Setting up caches with expiry of %v", defaultCacheTimeout))
	go e.containerIDCache.Start()
	go e.infoCache.Start()
	go e.auditLineCache.Start()

	nodeName := e.Getenv(config.NodeNameEnvKey)
	if nodeName == "" {
		err := fmt.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		e.logger.Error(err, "unable to run enricher")
		return err
	}

	e.logger.Info("Starting log-enricher on node: " + nodeName)

	e.logger.Info("Connecting to local GRPC server")
	var (
		conn          *grpc.ClientConn
		cancel        context.CancelFunc
		metricsClient apimetrics.Metrics_AuditIncClient
	)

	if err := util.Retry(func() (err error) {
		conn, cancel, err = e.Dial()
		if err != nil {
			return fmt.Errorf("connecting to local GRPC server: %w", err)
		}
		client := apimetrics.NewMetricsClient(conn)

		metricsClient, err = e.AuditInc(client)
		if err != nil {
			cancel()
			e.Close(conn)
			return fmt.Errorf("create metrics audit client: %w", err)
		}

		return nil
	}, func(err error) bool { return true }); err != nil {
		return fmt.Errorf("connect to local GRPC server: %w", err)
	}
	defer cancel()
	defer e.Close(conn)

	if err := e.startGrpcServer(); err != nil {
		return fmt.Errorf("start GRPC server: %w", err)
	}

	// Use auditd logs as main source or syslog as fallback.
	filePath := LogFilePath()

	// If the file does not exist, then tail will wait for it to appear
	tailFile, err := e.TailFile(
		filePath,
		tail.Config{
			ReOpen: true,
			Follow: true,
			Location: &tail.SeekInfo{
				Offset: 0,
				Whence: io.SeekEnd,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("tailing file: %w", err)
	}

	e.logger.Info("Reading from file " + filePath)
	for l := range e.Lines(tailFile) {
		if l.Err != nil {
			e.logger.Error(l.Err, "failed to tail")
			continue
		}

		line := l.Text
		e.logger.V(config.VerboseLevel).Info("Got line: " + line)
		if !IsAuditLine(line) {
			e.logger.V(config.VerboseLevel).Info("Not an audit line")
			continue
		}

		auditLine, err := ExtractAuditLine(line)
		if err != nil {
			e.logger.Error(err, "extract audit line")
			continue
		}

		e.logger.V(config.VerboseLevel).Info(fmt.Sprintf("Get container ID for PID: %d", auditLine.ProcessID))
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

		e.logger.V(config.VerboseLevel).Info("Get container info for: " + cID)
		info, err := e.getContainerInfo(nodeName, cID)
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

		err = e.dispatchAuditLine(metricsClient, nodeName, auditLine, info)
		if err != nil {
			e.logger.Error(
				err, "dispatch audit line")
			continue
		}

		// check if there's anything in the cache for this processID
		e.dispatchBacklog(metricsClient, nodeName, info, auditLine.ProcessID)
	}

	return fmt.Errorf("enricher failed: %w", e.Reason(tailFile))
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

	grpcServer := grpc.NewServer(
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.MaxRecvMsgSize(maxMsgSize),
	)
	apienricher.RegisterEnricherServer(grpcServer, e)

	go func() {
		if err := e.Serve(grpcServer, listener); err != nil {
			e.logger.Error(err, "unable to run GRPC server")
		}
	}()

	return nil
}

// Dial can be used to connect to the default GRPC server by creating a new
// client.
func Dial() (*grpc.ClientConn, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	//nolint:staticcheck // use this method until unsupported
	conn, err := grpc.DialContext(
		ctx,
		"unix://"+config.GRPCServerSocketEnricher,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("GRPC dial: %w", err)
	}
	return conn, cancel, nil
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
	if auditBacklog == nil {
		// nothing in the cache
		return
	}

	for i := range auditBacklog {
		auditLine := auditBacklog[i]
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
		e.dispatchApparmorLine(nodeName, auditLine, info)
	default:
		return fmt.Errorf("unknown audit line type %s", auditLine.AuditType)
	}

	return nil
}

func (e *Enricher) dispatchSelinuxLine(
	metricsClient apimetrics.Metrics_AuditIncClient,
	nodeName string,
	auditLine *types.AuditLine,
	info *types.ContainerInfo,
) {
	e.logger.Info("audit",
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
	)

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

	if info.RecordProfile != "" {
		for _, perm := range strings.Split(auditLine.Perm, " ") {
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

			a, _ := e.avcs.LoadOrStore(info.RecordProfile, sets.New[string]())
			stringSet, ok := a.(sets.Set[string])
			if ok {
				stringSet.Insert(string(jsonBytes))
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

	e.logger.Info("audit",
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
	)

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

	if info.RecordProfile != "" {
		s, _ := e.syscalls.LoadOrStore(info.RecordProfile, sets.New[string]())
		stringSet, ok := s.(sets.Set[string])
		if ok {
			stringSet.Insert(syscallName)
		}
	}
}

func (e *Enricher) dispatchApparmorLine(
	nodeName string,
	auditLine *types.AuditLine,
	info *types.ContainerInfo,
) {
	values := []interface{}{
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
		values = append(values, "extra", auditLine.ExtraInfo)
	}

	e.logger.Info("audit", values...)
}

// LogFilePath returns either the path to the audit logs or falls back to
// syslog if the audit log path does not exist.
func LogFilePath() string {
	filePath := config.SyslogLogPath
	if rutil.Exists(config.AuditLogPath) {
		filePath = config.AuditLogPath
	}
	return filePath
}
