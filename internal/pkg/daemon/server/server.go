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

package server

import (
	"context"
	"net"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"google.golang.org/grpc"

	api "sigs.k8s.io/security-profiles-operator/api/server"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

const (
	maxMsgSize = 16 * 1024 * 1024
)

// Server is the main structure of this package.
type Server struct {
	api.UnimplementedSecurityProfilesOperatorServer
	logger  logr.Logger
	metrics *metrics.Metrics
}

// New creates a new Server instance.
func New(logger logr.Logger, met *metrics.Metrics) *Server {
	return &Server{
		logger:  logger,
		metrics: met,
	}
}

// Start runs the server in the background.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", Addr())
	if err != nil {
		return errors.Wrap(err, "create listener")
	}

	grpcServer := grpc.NewServer(
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.MaxRecvMsgSize(maxMsgSize),
	)
	api.RegisterSecurityProfilesOperatorServer(grpcServer, s)

	go func() {
		s.logger.Info("Starting GRPC server API")
		if err := grpcServer.Serve(listener); err != nil {
			s.logger.Error(err, "unable to run GRPC server")
		}
	}()

	return nil
}

// Addr returns the default server listening address.
func Addr() string {
	return net.JoinHostPort("localhost", "9111")
}

// MetricSeccompProfileAuditInc updates the metrics for the seccomp audit
// counter.
func (s *Server) MetricsAuditInc(
	ctx context.Context, r *api.MetricsAuditRequest,
) (*api.EmptyResponse, error) {
	if r.GetType() == api.MetricsAuditRequest_SECCOMP {
		s.logger.Info("Updating seccomp audit metrics")
		s.metrics.IncSeccompProfileAudit(
			r.GetNode(),
			r.GetNamespace(),
			r.GetPod(),
			r.GetContainer(),
			r.GetExecutable(),
			r.GetSyscall(),
		)
	} else if r.GetType() == api.MetricsAuditRequest_SELINUX {
		s.logger.Info("Updating selinux audit metrics")
		s.metrics.IncSelinuxProfileAudit(
			r.GetNode(),
			r.GetNamespace(),
			r.GetPod(),
			r.GetContainer(),
			r.GetExecutable(),
			r.GetSyscall(),
		)
	}
	return &api.EmptyResponse{}, nil
}
