//go:build linux && !no_bpf

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

package bpfrecorder

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/kubernetes"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/bpfrecorderfakes"
)

// allPrograms are the programs of the compiled object.
var allPrograms = slices.Concat(baseHooks, appArmorHooks)

// fakePrograms makes the fake hand out a distinct program per name and returns
// a function which tells the names of the programs SetAutoload disabled.
func fakePrograms(mock *bpfrecorderfakes.FakeImpl) func() []string {
	progs := map[*libbpfgo.BPFProg]string{}
	byName := map[string]*libbpfgo.BPFProg{}

	for _, name := range allPrograms {
		prog := &libbpfgo.BPFProg{}
		progs[prog] = name
		byName[name] = prog
	}

	mock.ProgramNamesReturns(allPrograms)
	mock.GetProgramCalls(func(_ *libbpfgo.Module, name string) (*libbpfgo.BPFProg, error) {
		return byName[name], nil
	})

	return func() []string {
		var disabled []string

		for i := range mock.SetAutoloadCallCount() {
			prog, autoload := mock.SetAutoloadArgsForCall(i)
			if !autoload {
				disabled = append(disabled, progs[prog])
			}
		}

		return disabled
	}
}

// TestLoadDisablesUnusedPrograms asserts that the LSM programs are not loaded
// when they would not be attached: a kernel without the BPF LSM rejects them,
// and with them the whole object, which breaks seccomp recording as well.
func TestLoadDisablesUnusedPrograms(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		recordAppArmor bool
		lsmEnabled     bool
		wantDisabled   []string
	}{
		{name: "no BPF LSM", recordAppArmor: true, lsmEnabled: false, wantDisabled: appArmorHooks},
		{name: "AppArmor not recorded", recordAppArmor: false, lsmEnabled: true, wantDisabled: appArmorHooks},
		{name: "AppArmor recorded", recordAppArmor: true, lsmEnabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut := New("", logr.Discard(), true, tc.recordAppArmor)
			mock := &bpfrecorderfakes.FakeImpl{}
			mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
			mock.BPFLSMEnabledReturns(tc.lsmEnabled)
			sut.impl = mock

			disabled := fakePrograms(mock)

			require.NoError(t, sut.Load())
			require.ElementsMatch(t, tc.wantDisabled, disabled())

			// The object is loaded after the programs got disabled.
			require.Equal(t, 1, mock.BPFLoadObjectCallCount())

			attached := mock.AttachGenericCallCount()
			if tc.wantDisabled == nil {
				require.Equal(t, len(allPrograms), attached)
				require.True(t, sut.AppArmor.loaded)

				return
			}

			require.Equal(t, len(baseHooks), attached)

			if sut.AppArmor != nil {
				require.False(t, sut.AppArmor.loaded)
				require.ErrorIs(t, sut.AppArmor.StartRecording(sut), ErrStartBeforeLoad)
			}
		})
	}
}

func TestLoadFailsIfProgramCannotBeDisabled(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
	mock.SetAutoloadReturns(errTest)
	sut.impl = mock

	fakePrograms(mock)

	require.ErrorIs(t, sut.Load(), errTest)
	require.Zero(t, mock.BPFLoadObjectCallCount())
}

// TestProcessCacheLoadsOnlyExecHooks asserts that the process cache of the
// JSON enricher does not need more of the kernel than its exec hooks.
func TestProcessCacheLoadsOnlyExecHooks(t *testing.T) {
	t.Parallel()

	sut := NewBpfProcessCache(logr.Discard())
	mock := &bpfrecorderfakes.FakeImpl{}
	mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
	sut.recorder.impl = mock

	disabled := fakePrograms(mock)

	require.NoError(t, sut.Load())

	defer sut.Close()

	want := slices.DeleteFunc(slices.Clone(allPrograms), func(name string) bool {
		return slices.Contains(procCacheHooks, name)
	})
	require.ElementsMatch(t, want, disabled())
	require.Equal(t, len(procCacheHooks), mock.AttachGenericCallCount())

	_, _, events := mock.InitRingBufArgsForCall(0)
	require.Equal(t, eventsQueueSize, cap(events))
}

// TestLoadBuffersEvents asserts that the ring buffer is not drained into an
// unbuffered channel, which would make its poll wait for every single event.
func TestLoadBuffersEvents(t *testing.T) {
	t.Parallel()

	sut, mock := newRecordingRecorder(t, true, true)
	defer sut.Close()

	_, _, events := mock.InitRingBufArgsForCall(0)
	require.Equal(t, eventsQueueSize, cap(events))
}

func TestLoadInitializesInitComms(t *testing.T) {
	t.Parallel()

	sut, mock := newRecordingRecorder(t, true, false)
	defer sut.Close()

	var foundComms, foundExePrefix bool

	for i := range mock.InitGlobalVariableCallCount() {
		_, name, value := mock.InitGlobalVariableArgsForCall(i)

		switch name {
		case globalInitComms:
			foundComms = true

			comms, ok := value.([maxInitComms * taskCommLen]byte)
			require.True(t, ok)

			var got []string

			for n := range maxInitComms {
				if comm := strings.TrimRight(
					string(comms[n*taskCommLen:(n+1)*taskCommLen]), "\x00",
				); comm != "" {
					got = append(got, comm)
				}
			}

			require.Equal(t, containerInitComms, got)
		case globalInitExePrefix:
			foundExePrefix = true

			prefix, ok := value.([initExePrefixLen]byte)
			require.True(t, ok)
			require.Equal(t, "memfd:crun_cloned", strings.TrimRight(string(prefix[:]), "\x00"))
		}
	}

	require.True(t, foundComms)
	require.True(t, foundExePrefix)
}

// TestContainerInitComms asserts that the names of the init processes are
// the ones the kernel shows, which cuts them to taskCommLen-1 bytes, as they
// are matched exactly.
func TestContainerInitComms(t *testing.T) {
	t.Parallel()

	require.Subset(t, containerInitComms, []string{
		"runc:[2:INIT]",
		"youki:[2:INIT]",
		"crun",
		// crun executed from the memfd "crun_cloned:/proc/self/exe".
		("memfd:" + "crun_cloned:/proc/self/exe")[:taskCommLen-1],
	})

	for _, comm := range containerInitComms {
		require.Less(t, len(comm), taskCommLen, comm)
	}

	// The name of the memfd crun gets executed from on older kernels.
	require.True(t, strings.HasPrefix("memfd:crun_cloned:/proc/self/exe", containerInitExePrefix))
}

func TestInitExePrefixValue(t *testing.T) {
	t.Parallel()

	value, err := initExePrefixValue("memfd:x")
	require.NoError(t, err)
	require.Equal(t, "memfd:x", string(value[:7]))
	require.Equal(t, byte(0), value[7])

	_, err = initExePrefixValue(strings.Repeat("x", initExePrefixLen))
	require.Error(t, err, "the prefix has to leave room for the terminating NUL byte")

	_, err = initExePrefixValue(containerInitExePrefix)
	require.NoError(t, err)
}

func TestInitCommsValue(t *testing.T) {
	t.Parallel()

	value, err := initCommsValue([]string{"a", "crun"})
	require.NoError(t, err)
	require.Equal(t, byte('a'), value[0])
	require.Equal(t, byte(0), value[1])
	require.Equal(t, "crun", string(value[taskCommLen:taskCommLen+4]))
	require.Equal(t, byte(0), value[2*taskCommLen])

	_, err = initCommsValue(slices.Repeat([]string{"a"}, maxInitComms+1))
	require.Error(t, err)

	_, err = initCommsValue([]string{""})
	require.Error(t, err)

	_, err = initCommsValue([]string{strings.Repeat("x", taskCommLen)})
	require.Error(t, err, "the name has to leave room for the terminating NUL byte")

	_, err = initCommsValue(containerInitComms)
	require.NoError(t, err)
}

// TestClose asserts that the module is released once, and that nothing can be
// recorded with it afterwards.
func TestClose(t *testing.T) {
	t.Parallel()

	sut, mock := newRecordingRecorder(t, true, true)

	sut.Close()
	sut.Close()

	require.Equal(t, 1, mock.CloseModuleCallCount())
	require.Nil(t, sut.module)
	require.Nil(t, sut.Seccomp.syscalls)
	require.ErrorIs(t, sut.StartRecording(), ErrStartBeforeLoad)

	// The lost events reporter does not touch the released map.
	sut.checkLostEvents()
	require.Zero(t, mock.GetValueCallCount())
}

func TestCloseWithoutLoad(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock

	sut.Close()
	require.Zero(t, mock.CloseModuleCallCount())
}

// TestProfileRequestWithoutName asserts that a request without a profile name
// is rejected right away instead of running into the lookup retries.
func TestProfileRequestWithoutName(t *testing.T) {
	t.Parallel()

	sut, _ := newRecordingRecorder(t, true, true)
	t.Cleanup(sut.Close)

	for name, call := range map[string]func(*api.ProfileRequest) error{
		"SyscallsForProfile": func(r *api.ProfileRequest) error {
			_, err := sut.SyscallsForProfile(t.Context(), r)

			return err
		},
		"ResetSyscallsForProfile": func(r *api.ProfileRequest) error {
			_, err := sut.ResetSyscallsForProfile(t.Context(), r)

			return err
		},
		"ApparmorForProfile": func(r *api.ProfileRequest) error {
			_, err := sut.ApparmorForProfile(t.Context(), r)

			return err
		},
		"ResetApparmorForProfile": func(r *api.ProfileRequest) error {
			_, err := sut.ResetApparmorForProfile(t.Context(), r)

			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, r := range []*api.ProfileRequest{nil, {}} {
				err := call(r)
				require.Equal(t, codes.InvalidArgument, status.Code(err))
			}
		})
	}
}

// TestSyscallsForProfileStopsWithRequest asserts that the lookup of the keys
// of a profile does not keep retrying for a client which gave up.
func TestSyscallsForProfileStopsWithRequest(t *testing.T) {
	t.Parallel()

	sut, _ := newRecordingRecorder(t, true, false)
	defer sut.Close()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := sut.SyscallsForProfile(ctx, &api.ProfileRequest{Name: profile})
	require.ErrorIs(t, err, context.Canceled)
}

// TestNewPidEventExcludesKeysPastContainerLimit asserts that a container which
// creates keys in a loop cannot fill the maps for the other recorded ones.
func TestNewPidEventExcludesKeysPastContainerLimit(t *testing.T) {
	t.Parallel()

	logSink := &Logger{}
	sut := New("", logr.New(logSink), true, false)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock
	sut.clientset = &kubernetes.Clientset{}
	sut.uniqueKeys = true
	sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}
	sut.containerKeys = newContainerKeys(1)

	sut.containerIDToProfileMap.Insert(containerID, profile)
	mock.ContainerIDForPIDReturns(containerID, nil)

	generation := sut.recordingGeneration.Load()

	for key := range uint64(3) {
		sut.handleNewPidEvent(newPidEvent{pid: 42, mntns: 1, key: key + 1, generation: generation})
	}

	require.Equal(t, []uint64{1}, sut.containerKeys.Keys(containerID))

	// Both keys past the limit are excluded in the kernel.
	require.Equal(t, 2, mock.UpdateValue64CallCount())

	for i, want := range []uint64{2, 3} {
		_, key, _ := mock.UpdateValue64ArgsForCall(i)
		require.Equal(t, want, key)
	}

	warnings := 0

	for _, msg := range logSink.snapshot() {
		if strings.HasPrefix(msg, "Max keys per container reached") {
			warnings++
		}
	}

	require.Equal(t, 1, warnings, "the limit is reported once per container")
}

// TestSweepStaleKeysAfterSessionEnded asserts that a sweep which looked up the
// processes while the recording stopped does not drop data of the next one.
func TestSweepStaleKeysAfterSessionEnded(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(false, true)
	sut.activePidsBpfMap = &libbpfgo.BPFMap{}
	atomic.StoreInt64(&sut.startRequests, 1)

	sut.AppArmor.handleFileEvent(fileEvent(3, flagRead, "/etc/passwd"))
	mock.MapKeysReturns([][]byte{pidKey(200, 3)}, nil)

	stopDuringSweep := false

	mock.StatCalls(func(string) (os.FileInfo, error) {
		if stopDuringSweep {
			sut.recordingGeneration.Add(1)
		}

		return nil, os.ErrNotExist
	})

	sut.sweepStaleKeys()

	stopDuringSweep = true

	sut.sweepStaleKeys()
	require.Equal(t, []uint64{3}, sut.AppArmor.GetKnownKeys())
}

// TestAppArmorKeysAreBoundedForAllEvents asserts that sockets and capabilities
// count towards the tracked workloads like files do.
func TestAppArmorKeysAreBoundedForAllEvents(t *testing.T) {
	t.Parallel()

	sut := newTestAppArmorRecorder()

	for key := range uint64(maxTrackedKeys) {
		switch key % 3 {
		case 0:
			sut.handleFileEvent(fileEvent(key, flagRead, "/f"))
		case 1:
			sut.handleSocketEvent(&bpfEvent{Key: key, Flags: socketFlags(afInet, sockStream)})
		default:
			sut.handleCapabilityEvent(&bpfEvent{Key: key, Flags: 1})
		}
	}

	const next = uint64(maxTrackedKeys)

	sut.handleSocketEvent(&bpfEvent{Key: next, Flags: socketFlags(afInet, sockStream)})
	sut.handleCapabilityEvent(&bpfEvent{Key: next, Flags: 1})
	sut.handleFileEvent(fileEvent(next, flagRead, "/f"))

	require.NotContains(t, sut.recordedSocketsUse, recordingKey(next))
	require.NotContains(t, sut.recordedCapabilities, recordingKey(next))
	require.NotContains(t, sut.recordedFiles, recordingKey(next))
	require.True(t, sut.maxKeysWarned)

	// Dropping the data of a key frees its slot.
	sut.Clear([]uint64{0})
	sut.handleCapabilityEvent(&bpfEvent{Key: next, Flags: 1})
	require.Contains(t, sut.recordedCapabilities, recordingKey(next))
}

// TestUntrackedKeysAreReportedAgain asserts that the capabilities and sockets
// of a key which cannot be tracked yet are not marked as reported in the
// kernel, so that they are recorded once the key can be tracked.
func TestUntrackedKeysAreReportedAgain(t *testing.T) {
	t.Parallel()

	sut := newTestAppArmorRecorder()
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.bpf = mock
	sut.recordedCaps = &libbpfgo.BPFMap{}
	sut.recordedSockets = &libbpfgo.BPFMap{}

	for key := range uint64(maxTrackedKeys) {
		sut.handleFileEvent(fileEvent(key, flagRead, "/f"))
	}

	require.Zero(t, mock.DeleteKey64CallCount())

	const next = uint64(maxTrackedKeys)

	sut.handleCapabilityEvent(&bpfEvent{Key: next, Flags: 1})
	require.NotContains(t, sut.recordedCapabilities, recordingKey(next))
	require.Equal(t, 2, mock.DeleteKey64CallCount())

	sut.handleSocketEvent(&bpfEvent{Key: next, Flags: socketFlags(afInet, sockStream)})
	require.NotContains(t, sut.recordedSocketsUse, recordingKey(next))
	require.Equal(t, 4, mock.DeleteKey64CallCount())

	for i := range mock.DeleteKey64CallCount() {
		bpfMap, key := mock.DeleteKey64ArgsForCall(i)
		require.Contains(t, []*libbpfgo.BPFMap{sut.recordedCaps, sut.recordedSockets}, bpfMap)
		require.Equal(t, next, key)
	}

	// The events reported again once a slot is free get recorded.
	sut.Clear([]uint64{0})
	sut.handleCapabilityEvent(&bpfEvent{Key: next, Flags: 1})
	sut.handleSocketEvent(&bpfEvent{Key: next, Flags: socketFlags(afInet, sockStream)})
	require.Contains(t, sut.recordedCapabilities, recordingKey(next))
	require.Contains(t, sut.recordedSocketsUse, recordingKey(next))
}

// TestClearMakesKernelReportAgain asserts that the capabilities and sockets
// the BPF program reported once are reported again after their data got
// dropped.
func TestClearMakesKernelReportAgain(t *testing.T) {
	t.Parallel()

	sut := newTestAppArmorRecorder()
	mock := &bpfrecorderfakes.FakeImpl{}
	mock.DeleteKey64Returns(fmt.Errorf("wrapped: %w", errors.ErrUnsupported))
	sut.bpf = mock
	sut.recordedCaps = &libbpfgo.BPFMap{}
	sut.recordedSockets = &libbpfgo.BPFMap{}

	sut.Clear([]uint64{1, 2})

	require.Equal(t, 4, mock.DeleteKey64CallCount())

	keys := make([]uint64, 0, mock.DeleteKey64CallCount())

	for i := range mock.DeleteKey64CallCount() {
		bpfMap, key := mock.DeleteKey64ArgsForCall(i)
		require.Contains(t, []*libbpfgo.BPFMap{sut.recordedCaps, sut.recordedSockets}, bpfMap)

		keys = append(keys, key)
	}

	require.ElementsMatch(t, []uint64{1, 1, 2, 2}, keys)
}

// TestProcessedPathsFitIntoMessage asserts that the paths of a profile are
// bounded, so that its response fits into a gRPC message, and that the same
// paths are kept every time.
func TestProcessedPathsFitIntoMessage(t *testing.T) {
	t.Parallel()

	sut := newTestAppArmorRecorder()

	const (
		pathLen = 4000
		perKey  = 1000
	)

	for key := range uint64(2) {
		files := map[string]*fileAccess{}

		for i := range perKey {
			name := fmt.Sprintf("/%d/%d/", key, i)
			name += strings.Repeat("x", pathLen-len(name))
			files[name] = &fileAccess{read: true}
		}

		sut.recordedFiles[recordingKey(key)] = files
	}

	first, found := sut.processExecFsEvents([]uint64{0, 1})
	require.True(t, found)

	size := 0
	for _, path := range first.ReadOnlyPaths {
		size += len(path)
	}

	require.LessOrEqual(t, size, maxProfilePathBytes)
	require.Greater(t, size, maxProfilePathBytes-pathLen)

	second, _ := sut.processExecFsEvents([]uint64{0, 1})
	require.Equal(t, first, second)
}

// TestExecEventLengthsAreClamped asserts that lengths beyond the arrays of the
// event do not make the process cache panic.
func TestExecEventLengthsAreClamped(t *testing.T) {
	t.Parallel()

	event := getArgsEnvData()

	lenOffset := bpfEventHeaderSize + maxFileNameLen + maxArgs*maxArgLen + maxEnv*maxEnvLen
	binary.LittleEndian.PutUint32(event[lenOffset:], 1000)
	binary.LittleEndian.PutUint32(event[lenOffset+4:], 1000)

	sut := NewBpfProcessCache(logr.Discard())

	require.NotPanics(t, func() { sut.handleEvent(event) })

	cmdLine, err := sut.GetCmdLine(1)
	require.NoError(t, err)
	require.Equal(t, "arg1 --flag value with spaces last_arg", strings.TrimSpace(cmdLine))
}

// TestLoadWithoutAppArmorHook asserts that an AppArmor hook which cannot be
// attached does not fail loading the recorder: seccomp profiles can still be
// recorded, the AppArmor hooks attached before get detached again, and
// AppArmor profile requests fail with a clear error.
func TestLoadWithoutAppArmorHook(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
	mock.BPFLSMEnabledReturns(true)
	sut.impl = mock

	fakePrograms(mock)

	// The first AppArmor hook gets attached, the second one fails.
	failing := appArmorHooks[1]
	byProg := map[*libbpfgo.BPFProg]string{}

	for _, name := range allPrograms {
		prog, err := mock.GetProgram(nil, name)
		require.NoError(t, err)

		byProg[prog] = name
	}

	links := map[*libbpfgo.BPFLink]string{}

	mock.AttachGenericCalls(func(prog *libbpfgo.BPFProg) (*libbpfgo.BPFLink, error) {
		if byProg[prog] == failing {
			return nil, errTest
		}

		link := &libbpfgo.BPFLink{}
		links[link] = byProg[prog]

		return link, nil
	})

	require.NoError(t, sut.Load())

	defer sut.Close()

	// Only the AppArmor hook attached before the failing one got detached.
	require.Equal(t, 1, mock.DestroyLinkCallCount())
	require.Equal(t, appArmorHooks[0], links[mock.DestroyLinkArgsForCall(0)])

	require.False(t, sut.AppArmor.loaded)
	require.ErrorIs(t, sut.AppArmor.Unavailable(), ErrAppArmorUnavailable)
	require.ErrorIs(t, sut.AppArmor.Unavailable(), errTest)

	// Seccomp recording works.
	require.NoError(t, sut.StartRecording())
	require.NoError(t, sut.StopRecording())

	_, err := sut.Start(t.Context(), &api.RecordingRequest{})
	require.NoError(t, err)

	_, err = sut.ApparmorForProfile(t.Context(), &api.ProfileRequest{Name: "profile"})
	require.ErrorIs(t, err, ErrAppArmorUnavailable)
}
