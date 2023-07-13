//go:build !linux || no_bpf
// +build !linux no_bpf

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

package bpfrecorder

import (
	"context"
	"errors"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
)

var errUnsupported = errors.New("binary got compiled without bpf recorder support")

// BpfRecorder is the main structure of this package.
type BpfRecorder struct{}

// New returns a new BpfRecorder instance.
func New(logr.Logger) *BpfRecorder {
	return &BpfRecorder{}
}

// Run the BpfRecorder.
func (b *BpfRecorder) Run() error {
	return errUnsupported
}

// Dial can be used to connect to the default GRPC server by creating a new
// client.
func Dial() (*grpc.ClientConn, context.CancelFunc, error) {
	return nil, nil, errUnsupported
}

func (b *BpfRecorder) Start(
	context.Context, *api.EmptyRequest,
) (*api.EmptyResponse, error) {
	return nil, errUnsupported
}

func (b *BpfRecorder) Stop(
	context.Context, *api.EmptyRequest,
) (*api.EmptyResponse, error) {
	return nil, errUnsupported
}

// SyscallsForNamespace returns the syscall names for the provided PID.
func (b *BpfRecorder) SyscallsForProfile(
	context.Context, *api.ProfileRequest,
) (*api.SyscallsResponse, error) {
	return nil, errUnsupported
}
