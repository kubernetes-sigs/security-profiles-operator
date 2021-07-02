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
	"os"

	"github.com/nxadm/tail"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	api "sigs.k8s.io/security-profiles-operator/api/server"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/server"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
type impl interface {
	Getenv(key string) string
	Dial() (*grpc.ClientConn, error)
	Close(*grpc.ClientConn) error
	TailFile(filename string, config tail.Config) (*tail.Tail, error)
	Lines(tailFile *tail.Tail) chan *tail.Line
	Open(name string) (*os.File, error)
	InClusterConfig() (*rest.Config, error)
	NewForConfig(c *rest.Config) (*kubernetes.Clientset, error)
	ListPods(c *kubernetes.Clientset, nodeName string) (*v1.PodList, error)
	MetricsAuditInc(
		client api.SecurityProfilesOperatorClient,
		in *api.MetricsAuditRequest,
		opts ...grpc.CallOption,
	) (*api.EmptyResponse, error)
}

func (d *defaultImpl) Getenv(key string) string {
	return os.Getenv(key)
}

func (d *defaultImpl) Dial() (*grpc.ClientConn, error) {
	return grpc.Dial(server.Addr(), grpc.WithInsecure())
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

func (d *defaultImpl) Open(name string) (*os.File, error) {
	return os.Open(name)
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

func (d *defaultImpl) MetricsAuditInc(
	client api.SecurityProfilesOperatorClient,
	in *api.MetricsAuditRequest,
	opts ...grpc.CallOption,
) (*api.EmptyResponse, error) {
	return client.MetricsAuditInc(context.Background(), in, opts...)
}
