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

package enricher

import (
	"runtime"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
)

func TestSyscalls(t *testing.T) {
	t.Parallel()

	const profile = "profile"

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	_, err = sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.Equal(t, codes.NotFound, status.Code(err))
	require.ErrorContains(t, err, ErrorNoSyscalls)

	item, _ := sut.syscalls.GetOrSetFunc(profile, newSyncSet)
	item.Value().Insert("read", "write", "read")

	res, err := sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"read", "write"}, res.GetSyscalls())
	require.Equal(t, runtime.GOARCH, res.GetGoArch())

	// Another profile is not affected.
	_, err = sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: "other"})
	require.Equal(t, codes.NotFound, status.Code(err))

	_, err = sut.ResetSyscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.NoError(t, err)
	require.Nil(t, sut.syscalls.Get(profile))

	_, err = sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.Equal(t, codes.NotFound, status.Code(err))

	// Resetting a profile which is not recorded is fine.
	_, err = sut.ResetSyscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.NoError(t, err)
}

func TestAvcs(t *testing.T) {
	t.Parallel()

	const profile = "profile"

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	_, err = sut.Avcs(t.Context(), &api.AvcRequest{Profile: profile})
	require.Equal(t, codes.NotFound, status.Code(err))
	require.ErrorContains(t, err, ErrorNoAvcs)

	avcs := []*api.AvcResponse_SelinuxAvc{
		{Perm: "read", Scontext: "scontext", Tcontext: "tcontext", Tclass: "file"},
		{Perm: "write", Scontext: "scontext", Tcontext: "tcontext", Tclass: "file"},
	}

	item, _ := sut.avcs.GetOrSetFunc(profile, newSyncSet)

	for _, avc := range avcs {
		jsonBytes, err := protojson.Marshal(avc)
		require.NoError(t, err)

		item.Value().Insert(string(jsonBytes))
	}

	res, err := sut.Avcs(t.Context(), &api.AvcRequest{Profile: profile})
	require.NoError(t, err)
	require.Len(t, res.GetAvc(), len(avcs))

	perms := make([]string, 0, len(avcs))

	for _, avc := range res.GetAvc() {
		perms = append(perms, avc.GetPerm())

		require.Equal(t, "scontext", avc.GetScontext())
		require.Equal(t, "tcontext", avc.GetTcontext())
		require.Equal(t, "file", avc.GetTclass())
	}

	require.ElementsMatch(t, []string{"read", "write"}, perms)

	_, err = sut.ResetAvcs(t.Context(), &api.AvcRequest{Profile: profile})
	require.NoError(t, err)
	require.Nil(t, sut.avcs.Get(profile))

	_, err = sut.Avcs(t.Context(), &api.AvcRequest{Profile: profile})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestAvcsInvalidJson(t *testing.T) {
	t.Parallel()

	const profile = "profile"

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	item, _ := sut.avcs.GetOrSetFunc(profile, newSyncSet)
	item.Value().Insert("{")

	_, err = sut.Avcs(t.Context(), &api.AvcRequest{Profile: profile})
	require.ErrorContains(t, err, "unmarshall JSON")
}
