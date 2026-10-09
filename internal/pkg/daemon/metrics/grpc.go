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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	// MaxMsgSize is the largest message the metrics server receives and its
	// clients send.
	MaxMsgSize             = 16 * 1024 * 1024
	socketMode os.FileMode = 0o660

	// grpcStopTimeout bounds the graceful stop of the GRPC server. The log
	// enricher and the bpf recorder keep their streams open for as long as
	// they run, which a graceful stop would wait for.
	grpcStopTimeout = 5 * time.Second
)

// ServeGRPC runs the GRPC API server in the background.
func (m *Metrics) ServeGRPC() error {
	if _, err := os.Stat(config.GRPCServerSocketMetrics); err == nil {
		if err := os.RemoveAll(config.GRPCServerSocketMetrics); err != nil {
			return fmt.Errorf("remove GRPC socket file: %w", err)
		}
	}

	listener, err := net.Listen("unix", config.GRPCServerSocketMetrics)
	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}

	// The enrichers and the bpf recorder run as root without DAC_OVERRIDE, so
	// they connect through the group of the pod fsGroup, which the socket
	// inherits from the rootless daemon.
	if err := os.Chmod(config.GRPCServerSocketMetrics, socketMode); err != nil {
		return errors.Join(fmt.Errorf("change GRPC socket mode: %w", err), listener.Close())
	}

	m.grpcServer = grpc.NewServer(
		grpc.MaxSendMsgSize(MaxMsgSize),
		grpc.MaxRecvMsgSize(MaxMsgSize),
	)
	api.RegisterMetricsServer(m.grpcServer, m)

	go m.series.run(m.stopSeries)

	go func() {
		m.log.Info("Starting GRPC server API")

		if err := m.grpcServer.Serve(listener); err != nil {
			m.log.Error(err, "unable to run GRPC server")
		}
	}()

	return nil
}

// GracefulStop gracefully stops the GRPC server, and stops it forcefully if
// open streams keep it from stopping in time.
func (m *Metrics) GracefulStop() {
	if m.grpcServer != nil {
		stopGRPCServer(m.grpcServer, grpcStopTimeout, m.log)
	}

	m.stopOnce.Do(func() {
		close(m.stopSeries)
	})
}

// stopGRPCServer gracefully stops server, and stops it forcefully once timeout
// passed.
func stopGRPCServer(server *grpc.Server, timeout time.Duration, log logr.Logger) {
	stopped := make(chan struct{})

	go func() {
		server.GracefulStop()
		close(stopped)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-stopped:
	case <-timer.C:
		log.Info("Stopping GRPC server forcefully, streams are still open", "timeout", timeout)
		server.Stop()
		<-stopped
	}
}

// Dial can be used to connect to the default GRPC server by creating a new
// client.
func Dial() (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		"unix://"+config.GRPCServerSocketMetrics,
		dialOptions()...,
	)
	if err != nil {
		return nil, fmt.Errorf("GRPC dial: %w", err)
	}

	return conn, nil
}

func dialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// A request which exceeds the limit of the server has to fail with
		// ResourceExhausted on the client side. The server would otherwise
		// reset the stream, which makes Send fail like a broken transport.
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(MaxMsgSize)),
	}
}

// AuditInc updates the metrics for the audit counter.
func (m *Metrics) AuditInc(
	stream api.Metrics_AuditIncServer,
) error {
	for {
		r, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&api.EmptyResponse{})
		}

		if err != nil {
			return fmt.Errorf("record syscalls: %w", err)
		}

		switch {
		case r.GetSeccompReq() != nil:
			m.IncSeccompProfileAudit(
				r.GetNode(),
				r.GetNamespace(),
				r.GetPod(),
				r.GetContainer(),
				r.GetSeccompReq().GetSyscall(),
			)
		case r.GetSelinuxReq() != nil:
			m.IncSelinuxProfileAudit(
				r.GetNode(),
				r.GetNamespace(),
				r.GetPod(),
				r.GetContainer(),
				r.GetSelinuxReq().GetScontext(),
				r.GetSelinuxReq().GetTcontext(),
			)
		case r.GetApparmorReq() != nil:
			m.IncAppArmorProfileAudit(
				r.GetNode(),
				r.GetNamespace(),
				r.GetPod(),
				r.GetContainer(),
				r.GetApparmorReq().GetProfile(),
				r.GetApparmorReq().GetOperation(),
				r.GetApparmorReq().GetApparmor(),
			)
		}
	}
}

// BpfInc updates the metrics for the bpf counter.
func (m *Metrics) BpfInc(stream api.Metrics_BpfIncServer) error {
	for {
		r, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&api.EmptyResponse{})
		}

		if err != nil {
			return fmt.Errorf("record bpf metrics: %w", err)
		}

		m.IncSeccompProfileBpf(
			r.GetNode(),
			r.GetProfile(),
			r.GetMountNamespace(),
		)
	}
}
