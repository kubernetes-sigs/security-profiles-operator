/*
Copyright 2021 The Kubernetes Authors.

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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	defaultTimeout time.Duration = 20 * time.Second
	maxMsgSize                   = 16 * 1024 * 1024
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

	grpcServer := grpc.NewServer(
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.MaxRecvMsgSize(maxMsgSize),
	)
	api.RegisterMetricsServer(grpcServer, m)

	go func() {
		m.log.Info("Starting GRPC server API")
		if err := grpcServer.Serve(listener); err != nil {
			m.log.Error(err, "unable to run GRPC server")
		}
	}()

	return nil
}

// Dial can be used to connect to the default GRPC server by creating a new
// client.
func Dial() (*grpc.ClientConn, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	//nolint:staticcheck // we'll use this API once we have an appropriate alternative
	conn, err := grpc.DialContext(
		ctx,
		"unix://"+config.GRPCServerSocketMetrics,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("GRPC dial: %w", err)
	}
	return conn, cancel, nil
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

		if r.GetSeccompReq() != nil {
			m.IncSeccompProfileAudit(
				r.GetNode(),
				r.GetNamespace(),
				r.GetPod(),
				r.GetContainer(),
				r.GetExecutable(),
				r.GetSeccompReq().GetSyscall(),
			)
		} else if r.GetSelinuxReq() != nil {
			m.IncSelinuxProfileAudit(
				r.GetNode(),
				r.GetNamespace(),
				r.GetPod(),
				r.GetContainer(),
				r.GetExecutable(),
				r.GetSelinuxReq().GetScontext(),
				r.GetSelinuxReq().GetTcontext(),
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
