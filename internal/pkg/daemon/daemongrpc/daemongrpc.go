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

// Package daemongrpc holds the settings which the GRPC servers of the daemon
// containers, like the enricher, the bpf recorder and the metrics server, and
// their clients share.
package daemongrpc

import (
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// MaxMsgSize is the largest message the servers and their clients send and
// receive. The data recorded for a profile can exceed the default limit of
// the clients of 4 MiB.
const MaxMsgSize = 16 * 1024 * 1024

// ServerOptions returns the options of the servers.
func ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxSendMsgSize(MaxMsgSize),
		grpc.MaxRecvMsgSize(MaxMsgSize),
	}
}

// DialOptions returns the options of the clients, which receive what the
// servers send. A request which exceeds the limit of the server fails with
// ResourceExhausted on the client side. The server would otherwise reset the
// stream, which makes Send fail like a broken transport.
func DialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(MaxMsgSize),
			grpc.MaxCallRecvMsgSize(MaxMsgSize),
		),
	}
}

// Serve runs serve, which serves a GRPC server, in the background. The
// returned channel gets its error, unless the server got stopped, so that the
// container fails instead of running on with a socket nobody answers on.
func Serve(serve func() error) <-chan error {
	errs := make(chan error, 1)

	go func() {
		if err := serve(); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errs <- err
		}
	}()

	return errs
}

// Dial creates a client of the server listening on the unix socket.
func Dial(socket string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient("unix://"+socket, DialOptions()...)
	if err != nil {
		return nil, fmt.Errorf("GRPC dial: %w", err)
	}

	return conn, nil
}
