//go:build linux

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
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	apienricher "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	apimetrics "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

// newDispatchSut returns an enricher whose metrics go to the SendMetric of
// the returned fake.
func newDispatchSut(
	t *testing.T,
	filters []types.EnricherFilterOptions,
) (*Enricher, *enricherfakes.FakeImpl) {
	t.Helper()

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	mock := &enricherfakes.FakeImpl{}
	sut.impl = mock
	sut.enricherFilters = filters
	sut.metrics = metrics.NewContextSender(logr.Discard(), 10,
		func(context.Context) (metrics.Stream[*apimetrics.AuditRequest], func(), error) {
			return auditMetricsStream{e: sut}, func() {}, nil
		})

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	go sut.metrics.Run(ctx)

	return sut, mock
}

// sentMetric waits for a single metric and returns it.
func sentMetric(t *testing.T, mock *enricherfakes.FakeImpl) *apimetrics.AuditRequest {
	t.Helper()

	require.Eventually(t, func() bool {
		return mock.SendMetricCallCount() == 1
	}, time.Minute, time.Millisecond)

	_, req := mock.SendMetricArgsForCall(0)

	return req
}

// filterNamespace drops the records of the namespace.
func filterNamespace() []types.EnricherFilterOptions {
	return []types.EnricherFilterOptions{{
		Level:       types.EnricherLogLevelNone,
		MatchKeys:   []string{"namespace"},
		MatchValues: &[]string{namespace},
	}}
}

func selinuxTestLine() *types.AuditLine {
	return &types.AuditLine{
		AuditType:   types.AuditTypeSelinux,
		TimestampID: "1613173578.156:2945",
		ProcessID:   75593,
		Executable:  executable,
		Perm:        "read write",
		Scontext:    "system_u:system_r:container_t:s0:c4,c808",
		Tcontext:    "system_u:object_r:var_lib_t:s0",
		Tclass:      "lnk_file",
	}
}

func apparmorTestLine() *types.AuditLine {
	return &types.AuditLine{
		AuditType:   types.AuditTypeApparmor,
		TimestampID: "1668191154.949:64",
		ProcessID:   4166,
		Executable:  "tini",
		Apparmor:    "DENIED",
		Operation:   "exec",
		Profile:     "profile-name",
		Name:        "/usr/local/bin/sample-app",
		ExtraInfo:   "requested_mask='x' denied_mask='x'",
	}
}

func TestDispatchSelinuxLine(t *testing.T) {
	t.Parallel()

	info := &types.ContainerInfo{
		PodName: pod, Namespace: namespace, ContainerName: "container", RecordProfile: "profile",
	}

	sut, mock := newDispatchSut(t, nil)
	line := selinuxTestLine()

	require.NoError(t, sut.dispatchAuditLine(node, line, info))

	req := sentMetric(t, mock)
	require.Equal(t, node, req.GetNode())
	require.Equal(t, namespace, req.GetNamespace())
	require.Equal(t, pod, req.GetPod())
	require.Equal(t, "container", req.GetContainer())
	require.Equal(t, executable, req.GetExecutable())
	require.Equal(t, line.Scontext, req.GetSelinuxReq().GetScontext())
	require.Equal(t, line.Tcontext, req.GetSelinuxReq().GetTcontext())
	require.Nil(t, req.GetSeccompReq())

	// Every permission is recorded on its own.
	item := sut.avcs.Get("profile")
	require.NotNil(t, item)

	avcs := item.Value().UnsortedList()
	perms := make([]string, 0, len(avcs))

	for _, avcJSON := range avcs {
		avc := &apienricher.AvcResponse_SelinuxAvc{}
		require.NoError(t, protojson.Unmarshal([]byte(avcJSON), avc))
		require.Equal(t, line.Tclass, avc.GetTclass())

		perms = append(perms, avc.GetPerm())
	}

	require.ElementsMatch(t, []string{"read", "write"}, perms)
}

func TestDispatchSelinuxLineWithoutRecording(t *testing.T) {
	t.Parallel()

	sut, mock := newDispatchSut(t, nil)

	sut.dispatchSelinuxLine(node, selinuxTestLine(), &types.ContainerInfo{Namespace: namespace})

	sentMetric(t, mock)
	require.Zero(t, sut.avcs.Len())
}

// TestDispatchSelinuxLineFiltered asserts that a filtered line is neither
// logged nor counted, but still recorded.
func TestDispatchSelinuxLineFiltered(t *testing.T) {
	t.Parallel()

	sut, mock := newDispatchSut(t, filterNamespace())

	sut.dispatchSelinuxLine(node, selinuxTestLine(), &types.ContainerInfo{
		Namespace: namespace, RecordProfile: "profile",
	})

	require.NotNil(t, sut.avcs.Get("profile"))
	require.Never(t, func() bool {
		return mock.SendMetricCallCount() > 0
	}, 100*time.Millisecond, time.Millisecond)
}

func TestDispatchApparmorLine(t *testing.T) {
	t.Parallel()

	sut, mock := newDispatchSut(t, nil)
	line := apparmorTestLine()

	require.NoError(t, sut.dispatchAuditLine(node, line, &types.ContainerInfo{
		PodName: pod, Namespace: namespace, ContainerName: "container",
	}))

	req := sentMetric(t, mock)
	require.Equal(t, node, req.GetNode())
	require.Equal(t, namespace, req.GetNamespace())
	require.Equal(t, pod, req.GetPod())
	require.Equal(t, "container", req.GetContainer())
	require.Equal(t, "tini", req.GetExecutable())
	require.Equal(t, line.Profile, req.GetApparmorReq().GetProfile())
	require.Equal(t, line.Operation, req.GetApparmorReq().GetOperation())
	require.Equal(t, line.Apparmor, req.GetApparmorReq().GetApparmor())
	require.Equal(t, line.Name, req.GetApparmorReq().GetName())
	require.Nil(t, req.GetSelinuxReq())

	// AppArmor lines are not recorded.
	require.Zero(t, sut.avcs.Len())
	require.Zero(t, sut.syscalls.Len())
}

func TestDispatchApparmorLineFiltered(t *testing.T) {
	t.Parallel()

	sut, mock := newDispatchSut(t, filterNamespace())

	sut.dispatchApparmorLine(node, apparmorTestLine(), &types.ContainerInfo{Namespace: namespace})

	require.Never(t, func() bool {
		return mock.SendMetricCallCount() > 0
	}, 100*time.Millisecond, time.Millisecond)

	// Another namespace is not filtered.
	sut.dispatchApparmorLine(node, apparmorTestLine(), &types.ContainerInfo{Namespace: "other"})
	sentMetric(t, mock)
}

func TestDispatchAuditLineUnknownType(t *testing.T) {
	t.Parallel()

	sut, _ := newDispatchSut(t, nil)

	require.Error(
		t,
		sut.dispatchAuditLine(node, &types.AuditLine{AuditType: "unknown"}, &types.ContainerInfo{}),
	)
}

// TestDispatchSelinuxLineSkipsInvalidAvc asserts that an AVC which cannot be
// marshalled is not recorded: an empty entry would fail the Avcs RPC.
func TestDispatchSelinuxLineSkipsInvalidAvc(t *testing.T) {
	t.Parallel()

	sut, mock := newDispatchSut(t, nil)

	line := selinuxTestLine()
	line.Tcontext = "\xff"

	sut.dispatchSelinuxLine(node, line, &types.ContainerInfo{
		Namespace: namespace, RecordProfile: "profile",
	})

	sentMetric(t, mock)
	require.Zero(t, sut.avcs.Len())
}
