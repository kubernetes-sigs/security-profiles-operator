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

package metrics

import (
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
)

// newGRPCTestClient serves the metrics over a loopback listener and returns
// the client of it.
func newGRPCTestClient(t *testing.T, sut *Metrics) api.MetricsClient {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	api.RegisterMetricsServer(server, sut)

	serveErr := make(chan error, 1)

	go func() { serveErr <- server.Serve(listener) }()

	t.Cleanup(func() {
		server.Stop()
		require.NoError(t, <-serveErr)
	})

	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, conn.Close()) })

	return api.NewMetricsClient(conn)
}

// series returns the label values and values of the series of vec.
func series(t *testing.T, vec *prometheus.CounterVec) map[string]float64 {
	t.Helper()

	registry := prometheus.NewPedanticRegistry()
	require.NoError(t, registry.Register(vec))

	families, err := registry.Gather()
	require.NoError(t, err)

	result := map[string]float64{}

	for _, family := range families {
		for _, metric := range family.GetMetric() {
			result[labelsOf(metric)] = metric.GetCounter().GetValue()
		}
	}

	return result
}

// labelsOf joins the labels of a metric as name=value pairs.
func labelsOf(metric *dto.Metric) string {
	labels := ""

	for _, label := range metric.GetLabel() {
		if labels != "" {
			labels += ","
		}

		labels += label.GetName() + "=" + label.GetValue()
	}

	return labels
}

func TestAuditIncOverGRPC(t *testing.T) {
	t.Parallel()

	sut := New()
	client := newGRPCTestClient(t, sut)

	stream, err := client.AuditInc(t.Context())
	require.NoError(t, err)

	workload := &api.AuditRequest{
		Node: "node", Namespace: "namespace", Pod: "pod", Container: "container",
	}

	for _, req := range []*api.AuditRequest{
		{
			Node: workload.GetNode(), Namespace: workload.GetNamespace(),
			Pod: workload.GetPod(), Container: workload.GetContainer(),
			SeccompReq: &api.AuditRequest_SeccompAuditReq{Syscall: "read"},
		},
		{
			Node: workload.GetNode(), Namespace: workload.GetNamespace(),
			Pod: workload.GetPod(), Container: workload.GetContainer(),
			SeccompReq: &api.AuditRequest_SeccompAuditReq{Syscall: "read"},
		},
		{
			Node: workload.GetNode(), Namespace: workload.GetNamespace(),
			Pod: workload.GetPod(), Container: workload.GetContainer(),
			SelinuxReq: &api.AuditRequest_SelinuxAuditReq{
				Scontext: "scontext", Tcontext: "tcontext",
			},
		},
		{
			Node: workload.GetNode(), Namespace: workload.GetNamespace(),
			Pod: workload.GetPod(), Container: workload.GetContainer(),
			ApparmorReq: &api.AuditRequest_ApparmorAuditReq{
				Profile: "profile", Operation: "open", Apparmor: "DENIED", Name: "/etc/shadow",
			},
		},
		{
			Node: workload.GetNode(), Namespace: workload.GetNamespace(),
			Pod: workload.GetPod(), Container: workload.GetContainer(),
			ApparmorReq: &api.AuditRequest_ApparmorAuditReq{
				Profile: "profile", Operation: "open", Apparmor: "ALLOWED", Name: "/etc/passwd",
			},
		},
		// A request without a type is ignored.
		{Node: workload.GetNode()},
	} {
		require.NoError(t, stream.Send(req))
	}

	_, err = stream.CloseAndRecv()
	require.NoError(t, err)

	const workloadLabels = "container=container,namespace=namespace,node=node,pod=pod"

	require.Equal(t, map[string]float64{
		workloadLabels + ",syscall=read": 2,
	}, series(t, sut.metricSeccompProfileAudit))

	require.Equal(t, map[string]float64{
		workloadLabels + ",scontext=scontext,tcontext=tcontext": 1,
	}, series(t, sut.metricSelinuxProfileAudit))

	// The labels are sorted by name.
	const apparmorLabels = "container=container,namespace=namespace,node=node,operation=open,pod=pod,profile=profile"

	require.Equal(t, map[string]float64{
		"apparmor=DENIED," + apparmorLabels:  1,
		"apparmor=ALLOWED," + apparmorLabels: 1,
	}, series(t, sut.metricAppArmorProfileAudit))

	// Only the denied operation counts as a denial.
	require.Equal(t, map[string]float64{
		"operation=open,profile=profile": 1,
	}, series(t, sut.metricAppArmorProfileDenial))

	// The series are tracked, so that idle ones get dropped later on.
	sut.series.mu.Lock()
	defer sut.series.mu.Unlock()

	require.Len(t, sut.series.series, 4)
}

func TestBpfIncOverGRPC(t *testing.T) {
	t.Parallel()

	sut := New()
	client := newGRPCTestClient(t, sut)

	stream, err := client.BpfInc(t.Context())
	require.NoError(t, err)

	for range 3 {
		require.NoError(t, stream.Send(&api.BpfRequest{
			Node: "node", Profile: "profile", MountNamespace: 4026531840,
		}))
	}

	_, err = stream.CloseAndRecv()
	require.NoError(t, err)

	require.Equal(t, map[string]float64{
		"mount_namespace=4026531840,node=node,profile=profile": 3,
	}, series(t, sut.metricSeccompProfileBpf))
}
