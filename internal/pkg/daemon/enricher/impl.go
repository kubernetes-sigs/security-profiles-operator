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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/jellydator/ttlcache/v3"
	"github.com/nxadm/tail"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/auditsource"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

type defaultImpl struct {
	fsys fs.FS // Must be initialized by newDefaultImpl
}

func newDefaultImpl() *defaultImpl {
	return &defaultImpl{
		fsys: os.DirFS("/"),
	}
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	Getenv(key string) string
	Dial() (*grpc.ClientConn, context.CancelFunc, error)
	Close(*grpc.ClientConn) error
	StartTail(src auditsource.AuditLineSource) (chan *types.AuditLine, error)
	TailErr(src auditsource.AuditLineSource) error
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
	CmdlineForPID(pid int) (string, error)
	PrintJsonOutput(w io.Writer, output string)
	EnvForPid(pid int) (map[string]string, error)
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

func (d *defaultImpl) StartTail(src auditsource.AuditLineSource) (chan *types.AuditLine, error) {
	return src.StartTail()
}

func (d *defaultImpl) TailErr(src auditsource.AuditLineSource) error {
	return src.TailErr()
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

func (d *defaultImpl) CmdlineForPID(
	pid int,
) (string, error) {
	var retErr error

	cmdline := fmt.Sprintf("proc/%d/cmdline", pid)

	file, err := d.fsys.Open(filepath.Clean(cmdline))
	if err != nil {
		retErr = fmt.Errorf("%w: %w", ErrProcessNotFound, err)

		return "", retErr
	}

	defer func() {
		cerr := file.Close()
		if retErr == nil {
			retErr = cerr
		}
	}()

	var sb strings.Builder

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sb.WriteString(strings.ReplaceAll(scanner.Text(), "\u0000", " "))
	}

	if err := scanner.Err(); err != nil {
		retErr = fmt.Errorf("%w: %w", ErrCmdlineNotFound, err)

		return "", retErr
	}

	return sb.String(), retErr
}

func (d *defaultImpl) EnvForPid(pid int) (map[string]string, error) {
	var retErr error

	envFile := fmt.Sprintf("proc/%d/environ", pid)
	envMap := make(map[string]string)

	content, err := fs.ReadFile(d.fsys, filepath.Clean(envFile))
	if err != nil {
		retErr = fmt.Errorf("%w: %w", ErrProcessNotFound, err)

		return envMap, retErr
	}

	envVars := bytes.Split(content, []byte{0})

	for _, envVarBytes := range envVars {
		envVar := string(envVarBytes)
		if envVar == "" {
			continue
		}

		// Ignore keys with no values
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]
			envMap[key] = value
		}
	}

	return envMap, nil
}

func (d *defaultImpl) PrintJsonOutput(w io.Writer, output string) {
	_, err := fmt.Fprintln(w, output)
	if err != nil {
		fmt.Printf("error printing json output: %v", err)
	}
}
