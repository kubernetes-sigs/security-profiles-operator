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

	"github.com/pkg/errors"
	"google.golang.org/protobuf/encoding/protojson"
	"k8s.io/apimachinery/pkg/util/sets"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
)

// Syscalls returns the syscalls for a provided profile.
func (e *Enricher) Syscalls(
	ctx context.Context, r *api.SyscallsRequest,
) (*api.SyscallsResponse, error) {
	syscalls, ok := e.syscalls.Load(r.GetProfile())
	if !ok {
		return nil, errors.Errorf(
			"no syscalls recorded for profile: %v", r.GetProfile(),
		)
	}
	return &api.SyscallsResponse{Syscalls: syscalls.(sets.String).List()}, nil
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
		return nil, errors.Errorf(
			"no avcs recorded for profile: %v", r.GetProfile(),
		)
	}

	avcList := make([]*api.AvcResponse_SelinuxAvc, 0)
	jsonList := avcs.(sets.String).List()
	for i := range jsonList {
		avc := &api.AvcResponse_SelinuxAvc{}
		err := protojson.Unmarshal([]byte(jsonList[i]), avc)
		if err != nil {
			return nil, errors.Wrap(err, "unmarshall JSON")
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
