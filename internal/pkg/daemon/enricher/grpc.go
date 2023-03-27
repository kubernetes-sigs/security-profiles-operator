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

package enricher

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"k8s.io/apimachinery/pkg/util/sets"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
)

const (
	// ErrorNoSyscalls is returned when no syscalls are recorded for a profile.
	ErrorNoSyscalls = "no syscalls recorded for profile"
	// ErrorNoAvcs is returned when no AVCs are recorded for a profile.
	ErrorNoAvcs = "no avcs recorded for profile"
)

// Syscalls returns the syscalls for a provided profile.
func (e *Enricher) Syscalls(
	ctx context.Context, r *api.SyscallsRequest,
) (*api.SyscallsResponse, error) {
	syscalls, ok := e.syscalls.Load(r.GetProfile())
	if !ok {
		st := status.New(codes.NotFound, ErrorNoSyscalls)
		return nil, st.Err()
	}
	stringSet, ok := syscalls.(sets.Set[string])
	if !ok {
		return nil, errors.New("syscalls are no string set")
	}
	return &api.SyscallsResponse{
		Syscalls: stringSet.UnsortedList(),
		GoArch:   runtime.GOARCH,
	}, nil
}

// ResetSyscalls removes the syscalls for a provided profile.
func (e *Enricher) ResetSyscalls(
	ctx context.Context, r *api.SyscallsRequest,
) (*api.EmptyResponse, error) {
	e.syscalls.Delete(r.GetProfile())
	return &api.EmptyResponse{}, nil
}

// Avcs returns the AVC messages for a provided profile.
func (e *Enricher) Avcs(
	ctx context.Context, r *api.AvcRequest,
) (*api.AvcResponse, error) {
	avcs, ok := e.avcs.Load(r.GetProfile())
	if !ok {
		st := status.New(codes.NotFound, ErrorNoAvcs)
		return nil, st.Err()
	}

	avcList := make([]*api.AvcResponse_SelinuxAvc, 0)
	stringSet, ok := avcs.(sets.Set[string])
	if !ok {
		return nil, errors.New("avcs are no string set")
	}
	jsonList := stringSet.UnsortedList()
	for i := range jsonList {
		avc := &api.AvcResponse_SelinuxAvc{}
		err := protojson.Unmarshal([]byte(jsonList[i]), avc)
		if err != nil {
			return nil, fmt.Errorf("unmarshall JSON: %w", err)
		}
		avcList = append(avcList, avc)
	}

	return &api.AvcResponse{Avc: avcList}, nil
}

// ResetAvcs removes the avcs for a provided profile.
func (e *Enricher) ResetAvcs(
	ctx context.Context, r *api.AvcRequest,
) (*api.EmptyResponse, error) {
	e.avcs.Delete(r.GetProfile())
	return &api.EmptyResponse{}, nil
}
