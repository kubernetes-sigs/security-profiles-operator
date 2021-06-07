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
	"net"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"google.golang.org/grpc"

	api "sigs.k8s.io/security-profiles-operator/api/server"
)

const (
	maxMsgSize = 16 * 1024 * 1024
)

// Server is the main structure of this package.
type Server struct {
	logger logr.Logger
	api.UnimplementedSecurityProfilesOperatorServer
}

// New creates a new Server instance.
func New(logger logr.Logger) *Server {
	return &Server{
		logger: logger,
	}
}

// Start runs the server in the background.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", net.JoinHostPort("localhost", "9111"))
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
