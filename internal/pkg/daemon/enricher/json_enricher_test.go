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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/natefinch/lumberjack.v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex/podindextest"
)

const (
	nodeJsonTest         = "test-node"
	namespaceJsonTest    = "test-namespace"
	podJsonTest          = "test-pod"
	executableBusybox    = "/bin/busybox"
	executableNginx      = "/bin/nginx"
	syscallJsonTest      = "mprotect"
	crioPrefixJsonTest   = "cri-o://"
	seccompLineJsonTest1 = `type=SECCOMP msg=audit(1624537480.360:8477): auid=1000 ` +
		`uid=0 gid=0 ses=1 subj=kernel pid=2060394 comm="sleep" ` +
		`exe="` + executableBusybox + `" sig=0 arch=c000003e syscall=10 compat=0 ` +
		`ip=0x7f4ce626349b code=0x7ffc0000 AUID="user" UID="root" ` +
		`GID="root" ARCH=x86_64 SYSCALL=` + executableBusybox
	seccompLineJsonTest2 = `type=SECCOMP msg=audit(1624537480.360:8477): auid=1000 ` +
		`uid=0 gid=0 ses=1 subj=kernel pid=2060395 comm="sleep" ` +
		`exe="` + executableNginx + `" sig=0 arch=c000003e syscall=10 compat=0 ` +
		`ip=0x7f4ce626349b code=0x7ffc0000 AUID="user" UID="root" ` +
		`GID="root" ARCH=x86_64 SYSCALL=` + executableNginx
	containerIDJsonTest      = "218ce99dd8b33f6f9b6565863d7cd47dc880963ddd2cd987bcb2d330c65144bf"
	cmdLineJsonTest          = "/bin/sh "
	invalidLineJsonTest      = "this line is not a valid line for the parser"
	auditLogFlushTimeSeconds = 2
	// auditLogFlushSlackSeconds is how much later than the flush interval the
	// output may still arrive before the test calls it a failure.
	auditLogFlushSlackSeconds = 8
	envForJsonTest            = "KUBERNETES_SERVICE_PORT=443\nKUBERNETES_PORT=tcp://172.30.0.1:443\n" +
		"HOSTNAME=my-pod\nHOME=/root\nPKG_RELEASE=1~buster\nREQUEST_USER_NAME=containersetthis\n" +
		"SERVICE_URL=http://my-service.default.svc.cluster.local\nTERM=xterm\n" +
		"KUBERNETES_PORT_443_TCP_ADDR=172.30.0.1\nNGINX_VERSION=1.19.1\n" +
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" +
		"KUBERNETES_PORT_443_TCP_PORT=443\nNJS_VERSION=0.4.2\nKUBERNETES_PORT_443_TCP_PROTO=tcp\n" +
		"KUBERNETES_PORT_443_TCP=tcp://172.30.0.1:443\nKUBERNETES_SERVICE_PORT_HTTPS=443\n" +
		"KUBERNETES_SERVICE_HOST=172.30.0.1\nPWD=/\n" +
		"SPO_EXEC_REQUEST_UID=da83c434-91f0-4696-a04e-75d08b6d80b2\n" +
		"NSS_SDB_USE_CACHE=no"
)

func getEnvMap(content []byte) map[string]string {
	envMap := make(map[string]string)
	envVars := bytes.SplitSeq(content, []byte{'\n'})

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

	return envMap
}

func TestJsonEnricherNoOptions(t *testing.T) {
	t.Parallel()

	_, jErr := NewJsonEnricherArgs(logr.Discard(), nil)

	require.NoError(t, jErr)
}

func TestJsonEnricherFreqOptions(t *testing.T) {
	t.Parallel()

	opts := &JsonEnricherOptions{}
	opts.AuditFreq = time.Duration(auditLogFlushTimeSeconds) * time.Second

	_, jErr := NewJsonEnricherArgs(logr.Discard(), opts)

	require.NoError(t, jErr)
}

func TestJsonEnricherLogPathOptionsInvalid(t *testing.T) {
	t.Parallel()

	opts := &JsonEnricherOptions{}
	opts.AuditLogMaxBackups = -1

	_, jErr := NewJsonEnricherArgs(logr.Discard(), opts)

	require.Error(t, jErr)

	opts.AuditLogMaxBackups = 0
	opts.AuditLogMaxAge = -1

	_, jErr = NewJsonEnricherArgs(logr.Discard(), opts)
	require.Error(t, jErr)

	opts.AuditLogMaxAge = 0
	opts.AuditLogMaxSize = -1

	_, jErr = NewJsonEnricherArgs(logr.Discard(), opts)
	require.Error(t, jErr)
}

func TestJsonEnricherLogPathOptionsValid(t *testing.T) {
	t.Parallel()

	opts := &JsonEnricherOptions{}
	opts.AuditLogMaxBackups = 10
	opts.AuditLogMaxAge = 10
	opts.AuditLogMaxSize = 100
	opts.AuditLogPath = "/dev/null"

	_, jErr := NewJsonEnricherArgs(logr.Discard(), opts)

	require.NoError(t, jErr)
}

func TestJsonEnricherWithFilter(t *testing.T) {
	t.Parallel()

	opts := &JsonEnricherOptions{}
	opts.AuditLogMaxBackups = 10
	opts.AuditLogMaxAge = 10
	opts.AuditLogMaxSize = 100
	opts.AuditLogPath = "/dev/null"
	opts.EnricherFiltersJson = "[]"

	_, jErr := NewJsonEnricherArgs(logr.Discard(), opts)

	require.NoError(t, jErr)
}

func TestJsonEnricherWithInvalidFilter(t *testing.T) {
	t.Parallel()

	opts := &JsonEnricherOptions{}
	opts.AuditLogMaxBackups = 10
	opts.AuditLogMaxAge = 10
	opts.AuditLogMaxSize = 100
	opts.AuditLogPath = "/dev/null"
	opts.EnricherFiltersJson = "[" // invalid json.

	_, jErr := NewJsonEnricherArgs(logr.Discard(), opts)

	require.Error(t, jErr)
}

// startJsonRun runs the enricher in the background. The returned function
// cancels its context and returns the outcome of Run.
func startJsonRun(t *testing.T, sut *JsonEnricher) (stop func() error) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)

	go sut.Run(ctx, runErr)

	return func() error {
		cancel()

		select {
		case err := <-runErr:
			return err
		case <-time.After(time.Minute):
			t.Fatal("Run did not return")

			return nil
		}
	}
}

// jsonOutputs returns the emitted records.
func jsonOutputs(t *testing.T, mock *enricherfakes.FakeImpl) []map[string]any {
	t.Helper()

	outputs := make([]map[string]any, 0, mock.PrintJsonOutputCallCount())

	for i := range mock.PrintJsonOutputCallCount() {
		_, output := mock.PrintJsonOutputArgsForCall(i)

		auditMap := map[string]any{}
		require.NoError(t, json.Unmarshal(output, &auditMap))

		outputs = append(outputs, auditMap)
	}

	return outputs
}

func newJsonRunSut(
	t *testing.T,
	mock *enricherfakes.FakeImpl,
	opts *JsonEnricherOptions,
) *JsonEnricher {
	t.Helper()

	sut, err := NewJsonEnricherArgs(logr.Discard(), opts)
	require.NoError(t, err)

	sut.impl = mock
	sut.nodeName = nodeJsonTest

	mock.PodListerWatcherReturns(podindextest.New(v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podJsonTest,
			Namespace: namespaceJsonTest,
		},
		Status: v1.PodStatus{
			ContainerStatuses: []v1.ContainerStatus{{
				ContainerID: crioPrefixJsonTest + containerIDJsonTest,
			}},
		},
	}))

	return sut
}

func TestJsonRun(t *testing.T) {
	t.Parallel()

	for _, toFile := range []bool{false, true} {
		for name, tc := range map[string]struct {
			prepare func(*enricherfakes.FakeImpl)
			assert  func(*testing.T, *enricherfakes.FakeImpl, chan string)
		}{
			"sends the log after the flush interval": {
				prepare: func(mock *enricherfakes.FakeImpl) {},
				assert: func(t *testing.T, mock *enricherfakes.FakeImpl, lineChan chan string) {
					t.Helper()

					startTime := time.Now()

					lineChan <- seccompLineJsonTest1

					require.Eventually(t, func() bool {
						return mock.PrintJsonOutputCallCount() == 1
					}, time.Duration(auditLogFlushTimeSeconds+auditLogFlushSlackSeconds)*time.Second,
						time.Millisecond)

					// Not before the flush interval. The slack is absolute, not
					// a multiple of the flush time: a short flush interval would
					// otherwise leave a loaded CI runner only a second or two.
					require.Less(t, float64(auditLogFlushTimeSeconds), time.Since(startTime).Seconds())

					require.Equal(t, executableBusybox, jsonOutputs(t, mock)[0]["executable"])
				},
			},
			"sends multiple lines": {
				prepare: func(mock *enricherfakes.FakeImpl) {
					mock.CmdlineForPIDReturns(cmdLineJsonTest, nil)
					mock.EnvForPidReturns(getEnvMap([]byte(envForJsonTest)), nil)
				},
				assert: func(t *testing.T, mock *enricherfakes.FakeImpl, lineChan chan string) {
					t.Helper()

					lineChan <- seccompLineJsonTest1

					require.Eventually(t, func() bool {
						return mock.PrintJsonOutputCallCount() == 1
					}, time.Minute, time.Millisecond)

					lineChan <- seccompLineJsonTest2

					require.Eventually(t, func() bool {
						return mock.PrintJsonOutputCallCount() == 2
					}, time.Minute, time.Millisecond)

					outputs := jsonOutputs(t, mock)
					require.Equal(t, executableBusybox, outputs[0]["executable"])
					require.Equal(t, executableNginx, outputs[1]["executable"])
					//nolint:testifylint // cmdLineJsonTest is a command line, not JSON
					require.Equal(t, cmdLineJsonTest, outputs[1]["cmdLine"])
					require.Equal(t, "da83c434-91f0-4696-a04e-75d08b6d80b2", outputs[1]["requestUID"])
				},
			},
			"skips invalid lines": {
				prepare: func(mock *enricherfakes.FakeImpl) {},
				assert: func(t *testing.T, mock *enricherfakes.FakeImpl, lineChan chan string) {
					t.Helper()

					lineChan <- invalidLineJsonTest
					// The next send returns once the invalid line got processed.
					lineChan <- invalidLineJsonTest
				},
			},
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				lineChan := make(chan string)
				mock := &enricherfakes.FakeImpl{}
				mock.LinesReturns(lineChan)
				mock.ContainerIDForPIDReturns(containerIDJsonTest, 0, nil)
				tc.prepare(mock)

				opts := &JsonEnricherOptions{
					AuditFreq: time.Duration(auditLogFlushTimeSeconds) * time.Second,
				}

				if toFile {
					opts.AuditLogMaxBackups = 10
					opts.AuditLogPath = filepath.Join(t.TempDir(), "logs", "audit.log")
					opts.AuditLogMaxAge = 1
					opts.AuditLogMaxSize = 10
				}

				stop := startJsonRun(t, newJsonRunSut(t, mock, opts))

				tc.assert(t, mock, lineChan)

				require.NoError(t, stop())
				require.Equal(t, 1, mock.StopTailCallCount())
			})
		}
	}
}

// TestJsonRunFlushesOnShutdown asserts that the records which are still
// buffered are emitted before Run returns, and before the file is closed.
func TestJsonRunFlushesOnShutdown(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")

	lineChan := make(chan string)
	mock := &enricherfakes.FakeImpl{}
	mock.LinesReturns(lineChan)
	mock.ContainerIDForPIDReturns(containerIDJsonTest, 0, nil)

	var mu sync.Mutex

	mock.PrintJsonOutputCalls(func(w io.Writer, output []byte) {
		mu.Lock()
		defer mu.Unlock()

		newDefaultImpl(logr.Discard()).PrintJsonOutput(w, output)
	})

	sut := newJsonRunSut(t, mock, &JsonEnricherOptions{
		// Nothing is flushed before the shutdown.
		AuditFreq:          time.Hour,
		AuditLogPath:       path,
		AuditLogMaxBackups: 1,
	})

	stop := startJsonRun(t, sut)

	// Two syscalls of the same process end up in one record.
	lineChan <- seccompLineJsonTest1

	lineChan <- strings.Replace(seccompLineJsonTest1, "syscall=10", "syscall=11", 1)

	require.Zero(t, mock.PrintJsonOutputCallCount())
	require.NoError(t, stop())
	require.Equal(t, 1, mock.PrintJsonOutputCallCount())

	syscalls := jsonOutputs(t, mock)[0]["syscalls"]
	require.Len(t, syscalls, 2)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(content), executableBusybox)
	require.Equal(t, 1, strings.Count(string(content), "\n"))
}

// TestJsonRunResolvesContainerOnEmission asserts that a bucket gets the
// container its pod told only after the lines of the process were read.
func TestJsonRunResolvesContainerOnEmission(t *testing.T) {
	t.Parallel()

	creating := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podJsonTest, Namespace: namespaceJsonTest},
		Status: v1.PodStatus{
			ContainerStatuses: []v1.ContainerStatus{{Name: "container"}},
		},
	}

	lineChan := make(chan string)
	mock := &enricherfakes.FakeImpl{}
	mock.LinesReturns(lineChan)
	mock.ContainerIDForPIDReturns(containerIDJsonTest, 0, nil)

	sut := newJsonRunSut(t, mock, &JsonEnricherOptions{AuditFreq: time.Hour})

	pods := podindextest.New(creating)
	mock.PodListerWatcherReturns(pods)

	stop := startJsonRun(t, sut)

	lineChan <- seccompLineJsonTest1
	// The next send returns once the first line got processed.
	lineChan <- seccompLineJsonTest1

	running := creating.DeepCopy()
	running.Status.ContainerStatuses[0].ContainerID = crioPrefixJsonTest + containerIDJsonTest
	pods.Modify(running)

	require.Eventually(t, func() bool {
		_, err := sut.lookup.containers.get(containerIDJsonTest)

		return err == nil
	}, time.Minute, time.Millisecond)

	require.NoError(t, stop())

	outputs := jsonOutputs(t, mock)
	require.Len(t, outputs, 1)
	require.Equal(t, map[string]any{
		"pod": podJsonTest, "namespace": namespaceJsonTest, "container": "container",
	}, outputs[0]["resource"])
}

// TestJsonRunReturnsTailError asserts that Run reports the tail ending.
func TestJsonRunReturnsTailError(t *testing.T) {
	t.Parallel()

	lineChan := make(chan string)
	mock := &enricherfakes.FakeImpl{}
	mock.LinesReturns(lineChan)
	mock.ReasonReturns(errTest)

	sut := newJsonRunSut(t, mock, nil)
	runErr := make(chan error, 1)

	go sut.Run(t.Context(), runErr)

	close(lineChan)

	select {
	case err := <-runErr:
		require.ErrorIs(t, err, errTest)
	case <-time.After(time.Minute):
		t.Fatal("Run did not return")
	}
}

// TestJsonRunFailures asserts that the setup failures are reported.
func TestJsonRunFailures(t *testing.T) {
	t.Parallel()

	for name, prepare := range map[string]func(*enricherfakes.FakeImpl){
		"in-cluster config": func(mock *enricherfakes.FakeImpl) {
			mock.InClusterConfigReturns(nil, errTest)
		},
		"clientset": func(mock *enricherfakes.FakeImpl) {
			mock.NewForConfigReturns(nil, errTest)
		},
		"tail": func(mock *enricherfakes.FakeImpl) {
			mock.TailFileReturns(nil, errTest)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mock := &enricherfakes.FakeImpl{}
			prepare(mock)

			runErr := make(chan error, 1)
			newJsonRunSut(t, mock, nil).Run(t.Context(), runErr)

			require.ErrorIs(t, <-runErr, errTest)
		})
	}
}

// TestJsonRunSplitsBucketOnExecutableChange asserts that the syscalls of a
// PID which runs another executable, after an execve or a PID reuse, are not
// attributed to the previous one.
func TestJsonRunSplitsBucketOnExecutableChange(t *testing.T) {
	t.Parallel()

	lineChan := make(chan string)
	mock := &enricherfakes.FakeImpl{}
	mock.LinesReturns(lineChan)
	mock.ContainerIDForPIDReturns(containerIDJsonTest, 0, nil)

	stop := startJsonRun(t, newJsonRunSut(t, mock, &JsonEnricherOptions{AuditFreq: time.Hour}))

	lineChan <- seccompLineJsonTest1

	// The same PID, another executable and syscall.
	lineChan <- strings.NewReplacer(
		executableBusybox, executableNginx,
		"syscall=10", "syscall=11",
	).Replace(seccompLineJsonTest1)

	// The first bucket is emitted right away.
	require.Eventually(t, func() bool {
		return mock.PrintJsonOutputCallCount() == 1
	}, time.Minute, time.Millisecond)

	require.NoError(t, stop())

	outputs := jsonOutputs(t, mock)
	require.Len(t, outputs, 2)

	for _, output := range outputs {
		require.EqualValues(t, 2060394, output["pid"])
		require.Len(t, output["syscalls"], 1)
	}

	require.ElementsMatch(t,
		[]any{executableBusybox, executableNginx},
		[]any{outputs[0]["executable"], outputs[1]["executable"]},
	)
	require.NotEqual(t, outputs[0]["syscalls"], outputs[1]["syscalls"])
}

// TestJsonEnricherDefaultsMaxBackups asserts that rotated audit log files are
// not kept forever when neither a number nor an age is configured.
func TestJsonEnricherDefaultsMaxBackups(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		opts           JsonEnricherOptions
		wantMaxBackups int
		wantMaxAge     int
	}{
		"nothing configured": {
			wantMaxBackups: defaultAuditLogMaxBackups,
		},
		"max backups configured": {
			opts:           JsonEnricherOptions{AuditLogMaxBackups: 3},
			wantMaxBackups: 3,
		},
		"max age configured": {
			opts:       JsonEnricherOptions{AuditLogMaxAge: 7},
			wantMaxAge: 7,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			opts := tc.opts
			opts.AuditLogPath = filepath.Join(t.TempDir(), "audit.log")

			sut, err := NewJsonEnricherArgs(logr.Discard(), &opts)
			require.NoError(t, err)

			logger, ok := sut.logWriter.(*lumberjack.Logger)
			require.True(t, ok)
			require.Equal(t, tc.wantMaxBackups, logger.MaxBackups)
			require.Equal(t, tc.wantMaxAge, logger.MaxAge)
		})
	}

	// Stdout is not rotated.
	sut, err := NewJsonEnricherArgs(logr.Discard(), &JsonEnricherOptions{})
	require.NoError(t, err)
	require.Equal(t, io.Writer(os.Stdout), sut.logWriter)
}

// TestDispatchSeccompLineUidGid pins down how an unknown uid or gid is emitted.
// They are pointers so that a missing audit field is not reported as 0, which
// would attribute the record to root. Serializing the nil pointer would put
// null in the output instead, which breaks any consumer parsing these as
// integers, so the keys are left out entirely.
func TestDispatchSeccompLineUidGid(t *testing.T) {
	t.Parallel()

	uid := uint32(1000)
	gid := uint32(2000)

	for _, tc := range []struct {
		name     string
		uid, gid *uint32
		wantUID  any
		wantGID  any
	}{
		{name: "known uid and gid", uid: &uid, gid: &gid, wantUID: float64(1000), wantGID: float64(2000)},
		{name: "unknown uid and gid", uid: nil, gid: nil, wantUID: nil, wantGID: nil},
		{name: "only uid known", uid: &uid, gid: nil, wantUID: float64(1000), wantGID: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &enricherfakes.FakeImpl{}

			sut, err := NewJsonEnricherArgs(logr.Discard(), nil)
			require.NoError(t, err)

			sut.impl = mock

			sut.dispatchSeccompLine(&types.LogBucket{
				TimestampID: "1613173578.156:2945",
				ProcessInfo: &types.ProcessInfo{
					Pid: 1234,
					Uid: tc.uid,
					Gid: tc.gid,
				},
			}, "test-node")

			require.Equal(t, 1, mock.PrintJsonOutputCallCount())

			_, output := mock.PrintJsonOutputArgsForCall(0)

			auditMap := map[string]any{}
			require.NoError(t, json.Unmarshal(output, &auditMap))

			// A missing key, never an explicit null.
			if tc.wantUID == nil {
				assert.NotContains(t, string(output), `"uid"`)
			}

			if tc.wantGID == nil {
				assert.NotContains(t, string(output), `"gid"`)
			}

			assert.Equal(t, tc.wantUID, auditMap["uid"])
			assert.Equal(t, tc.wantGID, auditMap["gid"])
		})
	}
}

// TestJsonEnricherLogLinesCacheNoTouch asserts that reading a log bucket does
// not extend its lifetime. Buckets are only flushed on eviction, so touching
// them on every hit would keep a busy process from ever emitting its records.
func TestJsonEnricherLogLinesCacheNoTouch(t *testing.T) {
	t.Parallel()

	sut, err := NewJsonEnricherArgs(logr.Discard(), nil)
	require.NoError(t, err)

	item := sut.logLinesCache.Set(1, &types.LogBucket{}, time.Hour)
	expiresAt := item.ExpiresAt()

	// Touching the item from now on would move its expiry.
	require.Eventually(t, func() bool {
		return time.Now().Add(time.Hour).After(expiresAt)
	}, time.Minute, time.Microsecond)

	hit := sut.logLinesCache.Get(1)
	require.NotNil(t, hit)
	require.Equal(t, expiresAt, hit.ExpiresAt())
}

// TestJsonEnricherLockedLogBucketEmitted asserts that a line of a process
// whose bucket got emitted in the meantime starts a new bucket.
func TestJsonEnricherLockedLogBucketEmitted(t *testing.T) {
	t.Parallel()

	sut, err := NewJsonEnricherArgs(logr.Discard(), nil)
	require.NoError(t, err)

	emitted := &types.LogBucket{Emitted: true}
	sut.logLinesCache.Set(1, emitted, time.Hour)

	bucket, cached := sut.lockedLogBucket(&types.AuditLine{ProcessID: 1, TimestampID: "ts"})
	bucket.Mu.Unlock()

	require.False(t, cached)
	require.NotSame(t, emitted, bucket)
	require.Equal(t, "ts", bucket.TimestampID)
}

// fakeBpfProcesses is a BPF process cache which counts its lookups.
type fakeBpfProcesses struct {
	cmdLine     string
	env         map[string]string
	err         error
	cmdLineHits int
	envHits     int
}

func (f *fakeBpfProcesses) GetCmdLine(int) (string, error) {
	f.cmdLineHits++

	return f.cmdLine, f.err
}

func (f *fakeBpfProcesses) GetEnv(int) (map[string]string, error) {
	f.envHits++

	return f.env, f.err
}

// TestProcessEbpf asserts that the BPF process cache fills in what the
// process file system did not tell, and that a bucket looks it up only once.
func TestProcessEbpf(t *testing.T) {
	t.Parallel()

	const requestUID = "da83c434-91f0-4696-a04e-75d08b6d80b2"

	for name, tc := range map[string]struct {
		cache          *fakeBpfProcesses
		info           types.ProcessInfo
		wantCmdLine    string
		wantRequestUID *string
		wantLookups    int
	}{
		"fills in the command line and the request": {
			cache: &fakeBpfProcesses{
				cmdLine: cmdLineJsonTest,
				env:     map[string]string{requestIdEnv: requestUID},
			},
			wantCmdLine:    cmdLineJsonTest,
			wantRequestUID: new(requestUID),
			wantLookups:    1,
		},
		"keeps what the process file system told": {
			cache: &fakeBpfProcesses{cmdLine: "other", env: map[string]string{requestIdEnv: "other"}},
			info: types.ProcessInfo{
				CmdLine: cmdLineJsonTest, ExecRequestId: new(requestUID),
			},
			wantCmdLine:    cmdLineJsonTest,
			wantRequestUID: new(requestUID),
		},
		"process without request": {
			cache:       &fakeBpfProcesses{env: map[string]string{}},
			wantLookups: 1,
		},
		"process not in the cache": {
			cache:       &fakeBpfProcesses{err: errTest},
			wantLookups: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sut, err := NewJsonEnricherArgs(logr.Discard(), nil)
			require.NoError(t, err)

			sut.bpfProcessCache = tc.cache

			info := tc.info
			bucket := &types.LogBucket{ProcessInfo: &info}
			line := &types.AuditLine{ProcessID: 42}

			for range 3 {
				sut.processEbpf(bucket, line)
			}

			require.Equal(t, tc.wantCmdLine, bucket.ProcessInfo.CmdLine)
			require.Equal(t, tc.wantRequestUID, bucket.ProcessInfo.ExecRequestId)
			require.Equal(t, tc.wantLookups, tc.cache.envHits)
			require.LessOrEqual(t, tc.cache.cmdLineHits, 1)
		})
	}
}

// TestJsonRunAttributesLinesOfExitedProcess asserts that the lines of a
// process read after it exited get the container it was last seen running in,
// instead of no resource at all.
func TestJsonRunAttributesLinesOfExitedProcess(t *testing.T) {
	t.Parallel()

	lineChan := make(chan string)
	mock := &enricherfakes.FakeImpl{}
	mock.LinesReturns(lineChan)
	mock.ContainerIDForPIDReturnsOnCall(0, containerIDJsonTest, 0, nil)
	mock.ContainerIDForPIDReturns("", 0, os.ErrNotExist)

	stop := startJsonRun(t, newJsonRunSut(t, mock, &JsonEnricherOptions{AuditFreq: time.Hour}))

	// The process runs while its first line is read.
	lineChan <- seccompLineJsonTest1

	// It execs, and exits before the line of the new executable is read.
	lineChan <- strings.Replace(seccompLineJsonTest1, executableBusybox, executableNginx, 1)

	require.Eventually(t, func() bool {
		return mock.PrintJsonOutputCallCount() == 1
	}, time.Minute, time.Millisecond)

	require.NoError(t, stop())
	require.Equal(t, 2, mock.ContainerIDForPIDCallCount())

	outputs := jsonOutputs(t, mock)
	require.Len(t, outputs, 2)

	for _, output := range outputs {
		require.Equal(t, map[string]any{
			"pod": podJsonTest, "namespace": namespaceJsonTest, "container": "",
		}, output["resource"])
	}
}
