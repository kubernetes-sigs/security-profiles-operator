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
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/nxadm/tail"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
type impl interface {
	SetTTL(cache *ttlcache.Cache, ttl time.Duration) error
	Getenv(key string) string
	Dial() (*grpc.ClientConn, context.CancelFunc, error)
	Close(*grpc.ClientConn) error
	TailFile(filename string, config tail.Config) (*tail.Tail, error)
	Lines(tailFile *tail.Tail) chan *tail.Line
	Reason(tailFile *tail.Tail) error
	ContainerIDForPID(cache *ttlcache.Cache, pid int) (string, error)
	InClusterConfig() (*rest.Config, error)
	NewForConfig(c *rest.Config) (*kubernetes.Clientset, error)
	ListPods(c *kubernetes.Clientset, nodeName string) (*v1.PodList, error)
	AuditInc(client api.MetricsClient) (api.Metrics_AuditIncClient, error)
	SendMetric(client api.Metrics_AuditIncClient, in *api.AuditRequest) error
	Listen(string, string) (net.Listener, error)
	Serve(*grpc.Server, net.Listener) error
	AddToBacklog(cache *ttlcache.Cache, key string, data interface{}) error
	GetFromBacklog(cache *ttlcache.Cache, key string) (interface{}, error)
	FlushBacklog(cache *ttlcache.Cache, key string) error
	Chown(string, int, int) error
	Stat(string) (os.FileInfo, error)
	RemoveAll(string) error
}

func (d *defaultImpl) SetTTL(cache *ttlcache.Cache, ttl time.Duration) error {
	return cache.SetTTL(ttl)
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

func (d *defaultImpl) ContainerIDForPID(cache *ttlcache.Cache, pid int) (string, error) {
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
	c *kubernetes.Clientset, nodeName string,
) (*v1.PodList, error) {
	return c.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
}

func (d *defaultImpl) AuditInc(
	client api.MetricsClient,
) (api.Metrics_AuditIncClient, error) {
	return client.AuditInc(context.Background())
}

func (d *defaultImpl) AddToBacklog(
	cache *ttlcache.Cache, key string, value interface{},
) error {
	return cache.Set(key, value)
}

func (d *defaultImpl) GetFromBacklog(
	cache *ttlcache.Cache, key string,
) (interface{}, error) {
	return cache.Get(key)
}

func (d *defaultImpl) FlushBacklog(
	cache *ttlcache.Cache, key string,
) error {
	return cache.Remove(key)
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
