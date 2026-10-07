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
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/auditsource"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/tailer"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

type defaultImpl struct {
	fsys   fs.FS // Must be initialized by newDefaultImpl
	logger logr.Logger
}

func newDefaultImpl(logger logr.Logger) *defaultImpl {
	return &defaultImpl{
		fsys:   os.DirFS("/"),
		logger: logger,
	}
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	Dial() (*grpc.ClientConn, error)
	Close(*grpc.ClientConn) error
	StartTail(src auditsource.AuditLineSource) (chan *types.AuditLine, error)
	TailErr(src auditsource.AuditLineSource) error
	TailFile(filename string, config tailer.Config) (*tailer.Tailer, error)
	Lines(tailFile *tailer.Tailer) <-chan string
	Reason(tailFile *tailer.Tailer) error
	StopTail(tailFile *tailer.Tailer)
	ContainerIDForPID(cache *ttlcache.Cache[string, string], pid int) (string, error)
	InClusterConfig() (*rest.Config, error)
	NewForConfig(c *rest.Config) (*kubernetes.Clientset, error)
	PodListerWatcher(c kubernetes.Interface, nodeName string) podindex.ListerWatcher
	AuditInc(ctx context.Context, client api.MetricsClient) (api.Metrics_AuditIncClient, error)
	SendMetric(client api.Metrics_AuditIncClient, in *api.AuditRequest) error
	Listen(string, string) (net.Listener, error)
	Serve(*grpc.Server, net.Listener) error
	Chown(string, int, int) error
	Stat(string) (os.FileInfo, error)
	RemoveAll(string) error
	CmdlineForPID(pid int) (string, error)
	PrintJsonOutput(w io.Writer, output []byte)
	EnvForPid(pid int) (map[string]string, error)
	ProcessStartTime(pid int) (time.Duration, error)
}

func (d *defaultImpl) Dial() (*grpc.ClientConn, error) {
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
	filename string, config tailer.Config,
) (*tailer.Tailer, error) {
	return tailer.Follow(filename, config)
}

func (d *defaultImpl) Lines(tailFile *tailer.Tailer) <-chan string {
	return tailFile.Lines()
}

func (d *defaultImpl) Reason(tailFile *tailer.Tailer) error {
	return tailFile.Err()
}

func (d *defaultImpl) StopTail(tailFile *tailer.Tailer) {
	tailFile.Stop()
}

func (d *defaultImpl) ProcessStartTime(pid int) (time.Duration, error) {
	return util.ProcessStartTime(pid)
}

func (d *defaultImpl) ContainerIDForPID(
	cache *ttlcache.Cache[string, string],
	pid int,
) (string, error) {
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

func (d *defaultImpl) PodListerWatcher(
	c kubernetes.Interface, nodeName string,
) podindex.ListerWatcher {
	return podindex.NewListerWatcher(c, nodeName)
}

func (d *defaultImpl) AuditInc(
	ctx context.Context, client api.MetricsClient,
) (api.Metrics_AuditIncClient, error) {
	return client.AuditInc(ctx)
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

func (d *defaultImpl) CmdlineForPID(pid int) (string, error) {
	cmdline := fmt.Sprintf("proc/%d/cmdline", pid)

	// The arguments are separated by NUL bytes and may contain newlines, and
	// a command line can be longer than a line a scanner takes.
	content, err := fs.ReadFile(d.fsys, filepath.Clean(cmdline))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProcessNotFound, err)
	}

	return string(bytes.ReplaceAll(content, []byte{0}, []byte{' '})), nil
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

	envVars := bytes.SplitSeq(content, []byte{0})

	for envVarBytes := range envVars {
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

// newline is written after each record; a package-level value keeps it off the
// per-line allocation path.
var newline = []byte{'\n'}

func (d *defaultImpl) PrintJsonOutput(w io.Writer, output []byte) {
	// Write the marshalled bytes directly: converting to a string copies the
	// whole record and fmt.Fprintln adds a reflective formatting pass, once per
	// emitted audit line.
	// The newline goes out separately because appending it reallocates and
	// copies the record; callers hold the output mutex, so the two writes
	// cannot interleave.
	if _, err := w.Write(output); err != nil {
		d.logger.Error(err, "error printing json output")

		return
	}

	if _, err := w.Write(newline); err != nil {
		d.logger.Error(err, "error printing json output")
	}
}
