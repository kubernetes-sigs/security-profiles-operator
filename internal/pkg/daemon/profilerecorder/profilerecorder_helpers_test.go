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

package profilerecorder

import (
	"context"
	"runtime"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bpfrecorderapi "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	enricherapi "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	recordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/profilerecorder/profilerecorderfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

// testPodUID is the UID of the recorded pod, which the BPF recorder is started
// and stopped for.
const testPodUID types.UID = "pod-uid"

// fakeImpl combines the fakes of all concerns of impl. Each test stubs the
// methods it needs through the promoted methods of the embedded fakes.
type fakeImpl struct {
	*profilerecorderfakes.FakeKubernetesImpl
	*profilerecorderfakes.FakeBpfRecorderImpl
	*profilerecorderfakes.FakeEnricherImpl
	*profilerecorderfakes.FakeProfileImpl
}

func newFakeImpl() *fakeImpl {
	mock := &fakeImpl{
		FakeKubernetesImpl:  &profilerecorderfakes.FakeKubernetesImpl{},
		FakeBpfRecorderImpl: &profilerecorderfakes.FakeBpfRecorderImpl{},
		FakeEnricherImpl:    &profilerecorderfakes.FakeEnricherImpl{},
		FakeProfileImpl:     &profilerecorderfakes.FakeProfileImpl{},
	}

	// Recording is enabled for the namespaces of the pods by default, by the
	// recording webhook which the operator deploys for the SPOD.
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{}, nil)
	mock.GetNamespaceReturns(recordingNamespace(), nil)
	mock.GetMutatingWebhookConfigurationReturns(nil, kerrors.NewNotFound(
		admissionregv1.Resource("mutatingwebhookconfigurations"), bindata.MutatingWebhookConfigName,
	))

	return mock
}

// recordingNamespace returns a namespace which profile recording is enabled
// for.
func recordingNamespace() *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Labels: map[string]string{bindata.EnableRecordingLabel: ""},
	}}
}

// replacedPodMock returns a fake which records a pod with the BPF recorder
// and stores its seccomp profiles, together with the profile recording.
func replacedPodMock(t *testing.T, pod *corev1.Pod) *fakeImpl {
	t.Helper()

	recordings := bpfSeccompRecordingList()
	recordings.Items[0].Namespace = pod.Namespace

	mock := newFakeImpl()
	mock.GetPodReturns(pod, nil)
	mock.ListRecordingsReturns(recordings, nil)
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
	}, nil)
	mock.SyscallsForProfileReturns(&bpfrecorderapi.SyscallsResponse{
		Syscalls: []string{"read"},
		GoArch:   runtime.GOARCH,
	}, nil)
	mock.ClientGetCalls(func(
		_ context.Context, _ client.Client, _ types.NamespacedName, obj client.Object,
	) error {
		recording, ok := obj.(*recordingapi.ProfileRecording)
		require.True(t, ok)
		recordings.Items[0].DeepCopyInto(recording)

		return nil
	})
	mock.CreateOrUpdateCalls(func(
		_ context.Context, _ client.Client, _ client.Object, mutate controllerutil.MutateFn,
	) (controllerutil.OperationResult, error) {
		return controllerutil.OperationResultCreated, mutate()
	})

	return mock
}

// TestReconcileRecreatedPod asserts that a pod which got deleted and created
// again under the same name, with both events handled by one reconcile, gets
// the profiles of the previous pod collected and is recorded itself.
func TestReconcileRecreatedPod(t *testing.T) {
	t.Parallel()

	const previousProfile = "profile_ctr_previous_1600000000"

	request := reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "namespace", Name: "web-0"},
	}

	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      request.Name,
			Namespace: request.Namespace,
			UID:       "new",
			Annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "ctr": testAnnotationValue,
			},
		},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "ctr"}}},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}

	for _, tc := range []struct {
		name        string
		previousUID types.UID
		collectErr  error
	}{
		{name: "replaced pod", previousUID: "previous"},
		{name: "collection of the replaced pod fails", previousUID: "previous", collectErr: errTest},
		{name: "same pod", previousUID: "new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := replacedPodMock(t, newPod)
			if tc.collectErr != nil {
				mock.SyscallsForProfileReturns(nil, tc.collectErr)
			}

			sut := &RecorderReconciler{
				impl: mock, log: logr.Discard(), record: events.NewFakeRecorder(100),
			}
			sut.podsToWatch.Store(request.String(), podToWatch{
				baseName: request.NamespacedName,
				uid:      tc.previousUID,
				recorder: recordingapi.ProfileRecorderBpf,
				profiles: []profileToCollect{{
					kind: recordingapi.ProfileRecordingKindSeccompProfile,
					name: previousProfile,
				}},
			})

			_, err := sut.Reconcile(t.Context(), request)

			value, ok := sut.podsToWatch.Load(request.String())
			require.True(t, ok)

			watched, ok := value.(podToWatch)
			require.True(t, ok)

			switch {
			case tc.previousUID == newPod.UID:
				require.NoError(t, err)
				require.Zero(t, mock.SyscallsForProfileCallCount())
				require.Zero(t, mock.StartBpfRecorderCallCount())
				require.Zero(t, mock.DialBpfRecorderCallCount())
			case tc.collectErr != nil:
				// Retried with the next reconcile, the previous pod stays.
				require.ErrorIs(t, err, errTest)
				require.Equal(t, tc.previousUID, watched.uid)
				require.Zero(t, mock.StartBpfRecorderCallCount())
			default:
				require.NoError(t, err)

				require.Equal(t, 1, mock.SyscallsForProfileCallCount())
				_, _, req := mock.SyscallsForProfileArgsForCall(0)
				require.Equal(t, previousProfile, req.GetName())
				require.Equal(t, 1, mock.StopBpfRecorderCallCount())

				// The recorder is stopped for the previous pod only.
				_, _, stopReq := mock.StopBpfRecorderArgsForCall(0)
				require.Equal(t, string(tc.previousUID), stopReq.GetId())

				require.Equal(t, 1, mock.StartBpfRecorderCallCount())
				require.Equal(t, newPod.UID, watched.uid)
				require.Equal(t, testAnnotationValue, watched.profiles[0].name)

				_, _, startReq := mock.StartBpfRecorderArgsForCall(0)
				require.Equal(t, string(newPod.UID), startReq.GetId())

				// Collecting and starting share the connection. The SPOD is
				// read for the connection and for the recording namespaces.
				require.Equal(t, 1, mock.DialBpfRecorderCallCount())
				require.Equal(t, 2, mock.GetSPODCallCount())
			}
		})
	}
}

// TestCollectBpfProfilesUsesOneConnection asserts that collecting several
// profiles and stopping the recorder read the SPOD and dial only once.
func TestCollectBpfProfilesUsesOneConnection(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns"}}
	mock := replacedPodMock(t, pod)

	sut := &RecorderReconciler{
		impl:      mock,
		log:       logr.Discard(),
		record:    events.NewFakeRecorder(100),
		namespace: "operator-ns",
	}
	session := sut.newBpfRecorderSession()

	defer session.Close()

	require.NoError(t, sut.collectBpfProfiles(
		t.Context(), session, "", types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace},
		testPodUID,
		[]profileToCollect{
			{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "profile_a_nonce_1"},
			{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "profile_b_nonce_1"},
		}, nil,
	))

	require.Equal(t, 2, mock.SyscallsForProfileCallCount())
	require.Equal(t, 1, mock.StopBpfRecorderCallCount())
	require.Equal(t, 1, mock.DialBpfRecorderCallCount())
	require.Equal(t, 1, mock.GetSPODCallCount())

	// The SPOD is read from the operator namespace found at setup.
	_, _, namespace := mock.GetSPODArgsForCall(0)
	require.Equal(t, "operator-ns", namespace)
}

func TestBpfRecorderSessionKeepsError(t *testing.T) {
	t.Parallel()

	mock := newFakeImpl()
	mock.GetSPODReturns(nil, errTest)

	sut := &RecorderReconciler{impl: mock, log: logr.Discard()}
	session := sut.newBpfRecorderSession()

	for range 2 {
		_, err := session.Client(t.Context())
		require.ErrorIs(t, err, errTest)
	}

	require.Equal(t, 1, mock.GetSPODCallCount())

	session.Close()
}

func TestParseAnnotations(t *testing.T) {
	t.Parallel()

	kinds := []annotationKind{
		{prefix: "seccomp/", kind: recordingapi.ProfileRecordingKindSeccompProfile},
		{prefix: "apparmor/", kind: recordingapi.ProfileRecordingKindAppArmorProfile},
	}

	t.Run("sorted by annotation key", func(t *testing.T) {
		t.Parallel()

		annotations := map[string]string{
			"seccomp/c":  "c",
			"apparmor/a": "a",
			"seccomp/b":  "b",
			"other":      "ignored",
			"seccomp/a":  "sa",
			"apparmor/z": "z",
		}

		want := []profileToCollect{
			{kind: recordingapi.ProfileRecordingKindAppArmorProfile, name: "a"},
			{kind: recordingapi.ProfileRecordingKindAppArmorProfile, name: "z"},
			{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "sa"},
			{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "b"},
			{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "c"},
		}

		// Map iteration order is random, the result must not be.
		for range 20 {
			got, err := parseAnnotations(annotations, kinds)
			require.NoError(t, err)
			require.Equal(t, want, got)
		}
	})

	t.Run("empty profile is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := parseAnnotations(map[string]string{"seccomp/a": ""}, kinds)
		require.ErrorIs(t, err, errInvalidAnnotation)
	})

	t.Run("unrelated annotations", func(t *testing.T) {
		t.Parallel()

		got, err := parseAnnotations(map[string]string{"other": "", "x": "y"}, kinds)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("log and bpf annotations", func(t *testing.T) {
		t.Parallel()

		annotations := map[string]string{
			config.SeccompProfileRecordLogsAnnotationKey + "ctr":  "logs",
			config.SelinuxProfileRecordLogsAnnotationKey + "ctr":  "selinux",
			config.SeccompProfileRecordBpfAnnotationKey + "ctr":   "bpf",
			config.ApparmorProfileRecordBpfAnnotationKey + "ctr":  "apparmor",
			config.SeccompProfileRecordLogsAnnotationKey + "ctr2": "logs2",
		}

		logs, err := parseLogAnnotations(annotations)
		require.NoError(t, err)
		require.ElementsMatch(t, []profileToCollect{
			{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "logs"},
			{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "logs2"},
			{kind: recordingapi.ProfileRecordingKindSelinuxProfile, name: "selinux"},
		}, logs)

		bpf, err := parseBpfAnnotations(annotations)
		require.NoError(t, err)
		require.ElementsMatch(t, []profileToCollect{
			{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "bpf"},
			{kind: recordingapi.ProfileRecordingKindAppArmorProfile, name: "apparmor"},
		}, bpf)
	})
}

func TestParseProfileAnnotation(t *testing.T) {
	t.Parallel()

	parsed, err := parseProfileAnnotation("recording_ctr_nonce_1700000000")
	require.NoError(t, err)
	require.Equal(t, &parsedAnnotation{
		profileName: "recording",
		cntName:     "ctr",
		nonce:       "nonce",
		timestamp:   "1700000000",
	}, parsed)

	for _, invalid := range []string{
		"", "recording", "recording_ctr_nonce", "recording_ctr_nonce_1_extra",
	} {
		_, err := parseProfileAnnotation(invalid)
		require.Error(t, err, invalid)
	}
}

func TestCreateProfileName(t *testing.T) {
	t.Parallel()

	require.Equal(t,
		types.NamespacedName{Name: "recording-ctr", Namespace: "ns"},
		createProfileName("ctr", "", "ns", "recording"))
	require.Equal(t,
		types.NamespacedName{Name: "recording-ctr-abcde", Namespace: "ns"},
		createProfileName("ctr", "abcde", "ns", "recording"))
}

func avc(perm, tclass, tcontext string) *enricherapi.AvcResponse_SelinuxAvc {
	return &enricherapi.AvcResponse_SelinuxAvc{
		Perm:     perm,
		Tclass:   tclass,
		Scontext: "system_u:system_r:" + config.SelinuxPermissiveProfile + ":s0",
		Tcontext: tcontext,
	}
}

func TestSeProfileBuilder(t *testing.T) {
	t.Parallel()

	const fileContext = "system_u:object_r:container_file_t:s0"

	t.Run("merges the permissions per class and type", func(t *testing.T) {
		t.Parallel()

		sut := newSeProfileBuilder("usage", logr.Discard())
		require.NoError(t, sut.AddAvcList([]*enricherapi.AvcResponse_SelinuxAvc{
			avc("write", "file", fileContext),
			avc("read", "file", fileContext),
			avc("read", "file", fileContext),
			avc("open", "dir", fileContext),
			avc("signal", "process", "system_u:system_r:"+config.SelinuxPermissiveProfile+":s0"),
		}))

		// One entry per class and type, however many AVCs there were.
		require.Equal(t, []string{
			"file container_file_t",
			"dir container_file_t",
			"process " + config.SelinuxPermissiveProfile,
		}, sut.keys)

		policy, err := sut.Format()
		require.NoError(t, err)
		require.Equal(t, selinuxprofileapi.Allow{
			"container_file_t": {
				"file": {"read", "write"},
				"dir":  {"open"},
			},
			selinuxprofileapi.AllowSelf: {
				"process": {"signal"},
			},
		}, policy)
	})

	t.Run("malformed context", func(t *testing.T) {
		t.Parallel()

		sut := newSeProfileBuilder("usage", logr.Discard())
		require.Error(t, sut.AddAvcList([]*enricherapi.AvcResponse_SelinuxAvc{
			avc("read", "file", "container_file_t"),
		}))
	})

	t.Run("no AVCs", func(t *testing.T) {
		t.Parallel()

		policy, err := newSeProfileBuilder("usage", logr.Discard()).Format()
		require.NoError(t, err)
		require.Empty(t, policy)
	})
}
