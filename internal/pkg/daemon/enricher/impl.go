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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
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

const (
	// maxCmdlineBytes is the length of a command line which gets read.
	maxCmdlineBytes = 4 * 1024

	// maxEnvVarBytes is the length of an environment variable which gets
	// compared to the exec request ID, which is much shorter.
	maxEnvVarBytes = 4 * 1024
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

//go:generate go run -modfile=../../../../hack/tools/go.mod -mod=readonly github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
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
	// ContainerIDForPID returns the container ID of the process with the PID
	// and when it started, relative to the boot.
	ContainerIDForPID(
		cache *ttlcache.Cache[string, string], pid int,
	) (containerID string, started time.Duration, err error)
	InClusterConfig() (*rest.Config, error)
	NewForConfig(c *rest.Config) (*kubernetes.Clientset, error)
	PodListerWatcher(c kubernetes.Interface, nodeName string) podindex.ListerWatcher
	AuditInc(ctx context.Context, client api.MetricsClient) (api.Metrics_AuditIncClient, error)
	SendMetric(client api.Metrics_AuditIncClient, in *api.AuditRequest) error
	Listen(context.Context, string, string) (net.Listener, error)
	Serve(*grpc.Server, net.Listener) error
	Chown(string, int, int) error
	Stat(string) (os.FileInfo, error)
	RemoveAll(string) error
	CmdlineForPID(pid int) (string, error)
	PrintJsonOutput(w io.Writer, output []byte)
	ExecRequestIDForPID(pid int) (string, bool, error)
	ProcessStartTime(pid int) (time.Duration, error)
	Uptime() (time.Duration, error)
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

func (d *defaultImpl) Uptime() (time.Duration, error) {
	return uptime()
}

func (d *defaultImpl) ContainerIDForPID(
	cache *ttlcache.Cache[string, string],
	pid int,
) (containerID string, started time.Duration, err error) {
	return util.ContainerIDAndStartTimeForPID(cache, pid)
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

func (d *defaultImpl) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, network, address)
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

// CmdlineForPID returns the command line of the process, cut after
// maxCmdlineBytes: the process controls its length, and it gets cached.
func (d *defaultImpl) CmdlineForPID(pid int) (string, error) {
	f, err := d.fsys.Open(filepath.Clean(fmt.Sprintf("proc/%d/cmdline", pid)))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProcessNotFound, err)
	}
	defer f.Close()

	// The arguments are separated by NUL bytes and may contain newlines, and
	// a command line can be longer than a line a scanner takes.
	content, err := io.ReadAll(io.LimitReader(f, maxCmdlineBytes))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProcessNotFound, err)
	}

	return string(bytes.ReplaceAll(content, []byte{0}, []byte{' '})), nil
}

// ExecRequestIDForPID returns the exec request ID in the environment of the
// process and whether it has a non-empty one, see requestIdEnv. The
// environment is not kept, the process controls its size.
func (d *defaultImpl) ExecRequestIDForPID(pid int) (requestID string, found bool, err error) {
	f, err := d.fsys.Open(filepath.Clean(fmt.Sprintf("proc/%d/environ", pid)))
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", ErrProcessNotFound, err)
	}
	defer f.Close()

	prefix := []byte(requestIdEnv + "=")
	r := bufio.NewReaderSize(f, maxEnvVarBytes)

	for {
		entry, readErr := r.ReadSlice(0)

		// A variable which does not fit into the buffer is no request ID.
		long := false
		for errors.Is(readErr, bufio.ErrBufferFull) {
			long = true
			_, readErr = r.ReadSlice(0)
		}

		if !long {
			value, ok := bytes.CutPrefix(bytes.TrimSuffix(entry, []byte{0}), prefix)
			if ok && len(value) > 0 {
				return string(value), true, nil
			}
		}

		if errors.Is(readErr, io.EOF) {
			return "", false, nil
		}

		if readErr != nil {
			return "", false, fmt.Errorf("%w: %w", ErrProcessNotFound, readErr)
		}
	}
}

// PrintJsonOutput writes the record with its newline in a single write, so
// that a rotating log file never ends between the two. The record is owned by
// the caller and gets the newline appended.
func (d *defaultImpl) PrintJsonOutput(w io.Writer, output []byte) {
	if _, err := w.Write(append(output, '\n')); err != nil {
		d.logger.Error(err, "error printing json output")
	}
}
