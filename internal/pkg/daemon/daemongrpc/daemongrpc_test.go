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

package daemongrpc

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	apienricher "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
)

// largeSyscalls is above the default limit of 4 MiB of the clients.
var largeSyscalls = []string{strings.Repeat("a", 5*1024*1024)}

type largeResponseServer struct {
	apienricher.UnimplementedEnricherServer
}

func (largeResponseServer) Syscalls(
	context.Context, *apienricher.SyscallsRequest,
) (*apienricher.SyscallsResponse, error) {
	return &apienricher.SyscallsResponse{Syscalls: largeSyscalls}, nil
}

// A client receives responses up to the size the server may send.
func TestDialReceivesLargeMessages(t *testing.T) {
	t.Parallel()

	socket := filepath.Join(t.TempDir(), "grpc.sock")

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	require.NoError(t, err)

	server := grpc.NewServer(ServerOptions()...)
	apienricher.RegisterEnricherServer(server, largeResponseServer{})

	go func() { _ = server.Serve(listener) }() //nolint:errcheck // stopped by the cleanup

	t.Cleanup(server.Stop)

	conn, err := Dial(socket)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, conn.Close()) })

	resp, err := apienricher.NewEnricherClient(conn).Syscalls(
		t.Context(), &apienricher.SyscallsRequest{},
	)
	require.NoError(t, err)
	require.Equal(t, largeSyscalls, resp.GetSyscalls())
}

// Serve tells the error of the server, but not that it got stopped.
func TestServe(t *testing.T) {
	t.Parallel()

	errServe := errors.New("serve failed")

	require.ErrorIs(t, <-Serve(func() error { return errServe }), errServe)

	select {
	case err := <-Serve(func() error { return grpc.ErrServerStopped }):
		t.Fatalf("unexpected error %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}
