/*
Copyright 2025 The Kubernetes Authors.

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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/nxadm/tail"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
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
	auditLogFlushTimeSeconds = 5
	envForJsonTest           = "KUBERNETES_SERVICE_PORT=443\nKUBERNETES_PORT=tcp://172.30.0.1:443\n" +
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
	envVars := bytes.Split(content, []byte{'\n'})

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

func TestJsonRun(t *testing.T) {
	t.Parallel()

	type TestType int

	const (
		TestStdout TestType = iota
		TestFileOptions
	)

	testTypes := []TestType{
		TestStdout,
		TestFileOptions,
	}

	for _, testType := range testTypes {
		for _, tc := range []struct {
			runAsync bool
			prepare  func(*enricherfakes.FakeImpl, chan *tail.Line)
			assert   func(*enricherfakes.FakeImpl, chan *tail.Line, chan error)
		}{
			{ // test a basic case of sending the log
				runAsync: true,
				prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
					mock.GetenvReturns(nodeJsonTest)
					mock.LinesReturns(lineChan)
					mock.ContainerIDForPIDReturns(containerIDJsonTest, nil)
					mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
						ObjectMeta: metav1.ObjectMeta{
							Name:      podJsonTest,
							Namespace: namespaceJsonTest,
						},
						Status: v1.PodStatus{
							ContainerStatuses: []v1.ContainerStatus{{
								ContainerID: crioPrefixJsonTest + containerIDJsonTest,
							}},
						},
					}}}, nil)
				},
				assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err chan error) {
					for mock.LinesCallCount() != 1 {
						// Wait for Lines() to be called
					}

					// Ensure that time to get the log is around the time the
					startTime := time.Now()

					lineChan <- &tail.Line{
						Text: seccompLineJsonTest1,
						Time: time.Now(),
					}

					for mock.PrintJsonOutputCallCount() != 1 {
						// Wait for PrintJsonOutputCallCount() to be called
					}

					endTime := time.Now()
					executionTime := endTime.Sub(startTime)

					// Ensure that it's not less than flush time
					require.Less(t, float64(auditLogFlushTimeSeconds), executionTime.Seconds())

					// Ensure that it's not very long after the flush time
					require.Less(t, executionTime.Seconds(), float64(auditLogFlushTimeSeconds*2))

					auditMap := make(map[string]interface{})
					_, output := mock.PrintJsonOutputArgsForCall(0)
					errUnmarshal := json.Unmarshal([]byte(output), &auditMap)
					require.NoError(t, errUnmarshal)
					executable := auditMap["executable"]
					require.Equal(t, executableBusybox, executable)
				},
			},
			{ // test multiple lines
				runAsync: true,
				prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
					mock.GetenvReturns(nodeJsonTest)
					mock.LinesReturns(lineChan)
					mock.ContainerIDForPIDReturns(containerIDJsonTest, nil)
					mock.CmdlineForPIDReturns(cmdLineJsonTest, nil)
					mock.EnvForPidReturns(getEnvMap([]byte(envForJsonTest)), nil)
					mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
						ObjectMeta: metav1.ObjectMeta{
							Name:      podJsonTest,
							Namespace: namespaceJsonTest,
						},
						Status: v1.PodStatus{
							ContainerStatuses: []v1.ContainerStatus{{
								ContainerID: crioPrefixJsonTest + containerIDJsonTest,
							}},
						},
					}}}, nil)
				},
				assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err chan error) {
					for mock.LinesCallCount() != 1 {
						// Wait for Lines() to be called
					}

					lineChan <- &tail.Line{
						Text: seccompLineJsonTest1,
						Time: time.Now(),
					}

					for mock.PrintJsonOutputCallCount() != 1 {
						// Wait for PrintJsonOutputCallCount() to be called
					}

					lineChan <- &tail.Line{
						Text: seccompLineJsonTest2,
						Time: time.Now(),
					}

					for mock.PrintJsonOutputCallCount() != 2 {
						// Wait for PrintJsonOutputCallCount() to be called
					}

					auditMap := make(map[string]interface{})
					_, output := mock.PrintJsonOutputArgsForCall(0)
					errUnmarshal := json.Unmarshal([]byte(output), &auditMap)
					require.NoError(t, errUnmarshal)
					executable := auditMap["executable"]
					require.Equal(t, executableBusybox, executable)

					_, output = mock.PrintJsonOutputArgsForCall(1)
					errUnmarshal = json.Unmarshal([]byte(output), &auditMap)
					require.NoError(t, errUnmarshal)
					executable = auditMap["executable"]
					require.Equal(t, executableNginx, executable)
					//nolint:all
					require.Equal(t, cmdLineJsonTest, auditMap["cmdLine"])
					require.Equal(t, "da83c434-91f0-4696-a04e-75d08b6d80b2", auditMap["requestUID"])
				},
			},
			{ // test invalid
				runAsync: true,
				prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
					mock.GetenvReturns(nodeJsonTest)
					mock.LinesReturns(lineChan)
					mock.ContainerIDForPIDReturns(containerIDJsonTest, nil)
					mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
						ObjectMeta: metav1.ObjectMeta{
							Name:      podJsonTest,
							Namespace: namespaceJsonTest,
						},
						Status: v1.PodStatus{
							ContainerStatuses: []v1.ContainerStatus{{
								ContainerID: crioPrefixJsonTest + containerIDJsonTest,
							}},
						},
					}}}, nil)
				},
				assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err chan error) {
					for mock.LinesCallCount() != 1 {
						// Wait for Lines() to be called
					}

					lineChan <- &tail.Line{
						Text: invalidLineJsonTest,
						Time: time.Now(),
					}
				},
			},
		} {
			lineChan := make(chan *tail.Line)
			mock := &enricherfakes.FakeImpl{}
			tc.prepare(mock, lineChan)

			opts := &JsonEnricherOptions{}
			opts.AuditFreq = time.Duration(auditLogFlushTimeSeconds) * time.Second

			if testType == TestFileOptions {
				opts.AuditLogMaxBackups = 10
				opts.AuditLogPath = "/tmp/logs/audit.log"
				opts.AuditLogMaxAge = 1
				opts.AuditLogMaxSize = 10
			}

			sut, jErr := NewJsonEnricherArgs(logr.Discard(), opts)
			require.NoError(t, jErr)

			sut.impl = mock

			var err chan error

			if tc.runAsync {
				go func() { sut.Run(t.Context(), err) }()
			} else {
				sut.Run(t.Context(), err)
			}

			tc.assert(mock, lineChan, err)
		}
	}
}
