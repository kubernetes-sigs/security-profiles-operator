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
	"net"
	"os"

	"github.com/jellydator/ttlcache/v3"
	"github.com/nxadm/tail"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	Getenv(key string) string
	Dial() (*grpc.ClientConn, context.CancelFunc, error)
	Close(*grpc.ClientConn) error
	TailFile(filename string, config tail.Config) (*tail.Tail, error)
	Lines(tailFile *tail.Tail) chan *tail.Line
	Reason(tailFile *tail.Tail) error
	ContainerIDForPID(cache *ttlcache.Cache[string, string], pid int) (string, error)
	InClusterConfig() (*rest.Config, error)
	NewForConfig(c *rest.Config) (*kubernetes.Clientset, error)
	ListPods(ctx context.Context, c kubernetes.Interface, nodeName string) (*v1.PodList, error)
	AuditInc(client api.MetricsClient) (api.Metrics_AuditIncClient, error)
	SendMetric(client api.Metrics_AuditIncClient, in *api.AuditRequest) error
	Listen(string, string) (net.Listener, error)
	Serve(*grpc.Server, net.Listener) error
	AddToBacklog(cache *ttlcache.Cache[string, []*types.AuditLine], key string, value []*types.AuditLine)
	GetFromBacklog(cache *ttlcache.Cache[string, []*types.AuditLine], key string) []*types.AuditLine
	FlushBacklog(cache *ttlcache.Cache[string, []*types.AuditLine], key string)
	Chown(string, int, int) error
	Stat(string) (os.FileInfo, error)
	RemoveAll(string) error
}

func (d *defaultImpl) Getenv(key string) string {
	return os.Getenv(key)
}

func (d *defaultImpl) Dial() (*grpc.ClientConn, context.CancelFunc, error) {
	return metrics.Dial()
}

func (d *defaultImpl) Close(conn *grpc.ClientConn) error {
	return conn.Close()
}

func (d *defaultImpl) TailFile(
	filename string, config tail.Config,
) (*tail.Tail, error) {
	return tail.TailFile(filename, config)
}

func (d *defaultImpl) Lines(tailFile *tail.Tail) chan *tail.Line {
	return tailFile.Lines
}

func (d *defaultImpl) Reason(tailFile *tail.Tail) error {
	return tailFile.Err()
}

func (d *defaultImpl) ContainerIDForPID(cache *ttlcache.Cache[string, string], pid int) (string, error) {
	return util.ContainerIDForPID(cache, pid)
}

func (d *defaultImpl) InClusterConfig() (*rest.Config, error) {
	return rest.InClusterConfig()
}

func (d *defaultImpl) NewForConfig(
	c *rest.Config,
) (*kubernetes.Clientset, error) {
	return kubernetes.NewForConfig(c)
}

func (d *defaultImpl) ListPods(
	ctx context.Context, c kubernetes.Interface, nodeName string,
) (*v1.PodList, error) {
	return c.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
}

func (d *defaultImpl) AuditInc(
	client api.MetricsClient,
) (api.Metrics_AuditIncClient, error) {
	return client.AuditInc(context.Background())
}

func (d *defaultImpl) AddToBacklog(
	cache *ttlcache.Cache[string, []*types.AuditLine], key string, value []*types.AuditLine,
) {
	cache.Set(key, value, ttlcache.DefaultTTL)
}

func (d *defaultImpl) GetFromBacklog(
	cache *ttlcache.Cache[string, []*types.AuditLine], key string,
) []*types.AuditLine {
	item := cache.Get(key)
	if item == nil {
		return nil
	}
	return item.Value()
}

func (d *defaultImpl) FlushBacklog(
	cache *ttlcache.Cache[string, []*types.AuditLine], key string,
) {
	cache.Delete(key)
}

func (d *defaultImpl) SendMetric(
	client api.Metrics_AuditIncClient,
	in *api.AuditRequest,
) error {
	return client.Send(in)
}

func (d *defaultImpl) Serve(grpcServer *grpc.Server, listener net.Listener) error {
	return grpcServer.Serve(listener)
}

func (d *defaultImpl) Listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

func (d *defaultImpl) Chown(name string, uid, gid int) error {
	return os.Chown(name, uid, gid)
}

func (d *defaultImpl) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (d *defaultImpl) RemoveAll(path string) error {
	return os.RemoveAll(path)
}
