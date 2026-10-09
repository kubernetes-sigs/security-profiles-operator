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

// containerID is the ID of the recorded container, also in the tests which
// only build on Linux.
const containerID = "218ce99dd8b33f6f9b6565863d7cd47dc880963ddd2cd987bcb2d330c65144bf"

func TestSyscalls(t *testing.T) {
	t.Parallel()

	const profile = "profile"

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	_, err = sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.Equal(t, codes.NotFound, status.Code(err))
	require.ErrorContains(t, err, ErrorNoSyscalls)

	require.True(t, sut.syscalls.insert(profile, containerID, "read", "write", "read"))

	res, err := sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"read", "write"}, res.GetSyscalls())
	require.Equal(t, runtime.GOARCH, res.GetGoArch())

	// Another profile is not affected.
	_, err = sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: "other"})
	require.Equal(t, codes.NotFound, status.Code(err))

	_, err = sut.ResetSyscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.NoError(t, err)
	require.Zero(t, sut.syscalls.data.Len())

	_, err = sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.Equal(t, codes.NotFound, status.Code(err))

	// The lines read after the reset are not recorded again.
	require.False(t, sut.syscalls.insert(profile, containerID, "close"))
	require.Zero(t, sut.syscalls.data.Len())

	// Resetting a profile which is not recorded is fine.
	_, err = sut.ResetSyscalls(t.Context(), &api.SyscallsRequest{Profile: "other"})
	require.NoError(t, err)
}

// TestSyscallsCollect asserts that collecting a profile stops its recording,
// so that the collected syscalls are all that the reset drops, and keeps them
// for a retried collection.
func TestSyscallsCollect(t *testing.T) {
	t.Parallel()

	const profile = "profile"

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	require.True(t, sut.syscalls.insert(profile, containerID, "read"))

	request := &api.SyscallsRequest{Profile: profile, Collect: true}

	res, err := sut.Syscalls(t.Context(), request)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"read"}, res.GetSyscalls())

	// A line read between collecting and resetting is dropped.
	require.False(t, sut.syscalls.insert(profile, containerID, "write"))

	res, err = sut.Syscalls(t.Context(), request)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"read"}, res.GetSyscalls())

	_, err = sut.ResetSyscalls(t.Context(), request)
	require.NoError(t, err)
	require.Zero(t, sut.syscalls.data.Len())

	// Collecting a profile without syscalls does not stop its recording, a
	// pod which starts with the same profile later records it.
	_, err = sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: "empty", Collect: true})
	require.Equal(t, codes.NotFound, status.Code(err))
	require.True(t, sut.syscalls.insert("empty", containerID, "read"))

	// Fetching without collecting does not stop the recording.
	_, err = sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: "other"})
	require.Equal(t, codes.NotFound, status.Code(err))
	require.True(t, sut.syscalls.insert("other", containerID, "read"))
}

// TestSyscallsCollectPerContainer asserts that collecting a profile only stops
// the recording of the containers which recorded it. A container which starts
// with the same profile afterwards, like one of a pod cloned from a recorded
// one, is recorded and keeps its data over the reset of the collected ones.
func TestSyscallsCollectPerContainer(t *testing.T) {
	t.Parallel()

	const (
		profile = "profile"
		later   = "later"
	)

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	require.True(t, sut.syscalls.insert(profile, containerID, "read"))

	request := &api.SyscallsRequest{Profile: profile, Collect: true}

	res, err := sut.Syscalls(t.Context(), request)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"read"}, res.GetSyscalls())

	// The collected container is not recorded anymore, a new one is.
	require.False(t, sut.syscalls.insert(profile, containerID, "write"))
	require.True(t, sut.syscalls.insert(profile, later, "close"))

	_, err = sut.ResetSyscalls(t.Context(), request)
	require.NoError(t, err)

	res, err = sut.Syscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"close"}, res.GetSyscalls())

	require.False(t, sut.syscalls.insert(profile, containerID, "write"))
	require.True(t, sut.syscalls.insert(profile, later, "open"))

	// The recording of the new container gets collected on its own.
	res, err = sut.Syscalls(t.Context(), request)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"close", "open"}, res.GetSyscalls())

	_, err = sut.ResetSyscalls(t.Context(), request)
	require.NoError(t, err)
	require.Zero(t, sut.syscalls.data.Len())
	require.False(t, sut.syscalls.insert(profile, later, "write"))
}

// TestSyscallsResetWithoutCollect asserts that a reset without a collection
// before, like the one of a released pod, drops the data of all containers.
func TestSyscallsResetWithoutCollect(t *testing.T) {
	t.Parallel()

	const profile = "profile"

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	require.True(t, sut.syscalls.insert(profile, containerID, "read"))
	require.True(t, sut.syscalls.insert(profile, "other", "write"))

	_, err = sut.ResetSyscalls(t.Context(), &api.SyscallsRequest{Profile: profile})
	require.NoError(t, err)
	require.Zero(t, sut.syscalls.data.Len())

	require.False(t, sut.syscalls.insert(profile, containerID, "read"))
	require.False(t, sut.syscalls.insert(profile, "other", "write"))
	require.True(t, sut.syscalls.insert(profile, "new", "close"))
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

	for _, avc := range avcs {
		jsonBytes, err := protojson.Marshal(avc)
		require.NoError(t, err)

		require.True(t, sut.avcs.insert(profile, containerID, string(jsonBytes)))
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
	require.Zero(t, sut.avcs.data.Len())

	_, err = sut.Avcs(t.Context(), &api.AvcRequest{Profile: profile})
	require.Equal(t, codes.NotFound, status.Code(err))

	// The lines read after the reset are not recorded again.
	require.False(t, sut.avcs.insert(profile, containerID, "{}"))
}

// TestAvcsCollect asserts that collecting a profile stops its recording, and
// keeps the AVCs for a retried collection.
func TestAvcsCollect(t *testing.T) {
	t.Parallel()

	const profile = "profile"

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	require.True(t, sut.avcs.insert(profile, containerID, `{"perm":"read"}`))

	request := &api.AvcRequest{Profile: profile, Collect: true}

	for range 2 {
		res, err := sut.Avcs(t.Context(), request)
		require.NoError(t, err)
		require.Len(t, res.GetAvc(), 1)
		require.Equal(t, "read", res.GetAvc()[0].GetPerm())

		// A line read between collecting and resetting is dropped.
		require.False(t, sut.avcs.insert(profile, containerID, `{"perm":"write"}`))
	}

	_, err = sut.ResetAvcs(t.Context(), request)
	require.NoError(t, err)
	require.Zero(t, sut.avcs.data.Len())
}

func TestAvcsInvalidJson(t *testing.T) {
	t.Parallel()

	const profile = "profile"

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	require.True(t, sut.avcs.insert(profile, containerID, "{"))

	_, err = sut.Avcs(t.Context(), &api.AvcRequest{Profile: profile})
	require.ErrorContains(t, err, "unmarshall JSON")
}
