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
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	bpfrecorderapi "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	enricherapi "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	recordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/profilerecorder/profilerecorderfakes"
)

var errTest = errors.New("error")

func ptrTrue() *bool {
	b := true

	return &b
}

func TestName(t *testing.T) {
	t.Parallel()

	sut := NewController()
	assert.Equal(t, "recorder-spod", sut.Name())
}

func TestCollectBpfProfilesProfileName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		mergeStrategy recordingapi.ProfileMergeStrategy
		podName       string
		replicaSuffix string
		expected      string
	}{
		{
			name:          "fixed pod with containers merge",
			mergeStrategy: recordingapi.ProfileMergeContainers,
			podName:       "fixed-pod",
			expected:      "recording-container-fixed-pod",
		},
		{
			name:          "fixed pod without merge",
			mergeStrategy: recordingapi.ProfileMergeNone,
			podName:       "fixed-pod",
			expected:      "recording-container",
		},
		{
			name:          "generated pod keeps replica suffix",
			mergeStrategy: recordingapi.ProfileMergeContainers,
			podName:       "generated-abcde",
			replicaSuffix: "abcde",
			expected:      "recording-container-abcde",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recording := &recordingapi.ProfileRecording{
				ObjectMeta: metav1.ObjectMeta{Name: "recording", Namespace: "recording-ns"},
				Spec: recordingapi.ProfileRecordingSpec{
					MergeStrategy: tc.mergeStrategy,
				},
			}
			scheme := apiruntime.NewScheme()
			require.NoError(t, recordingapi.AddToScheme(scheme))
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(recording).Build()

			mock := &profilerecorderfakes.FakeImpl{}
			mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
				Spec: spodapi.SPODSpec{
					Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()},
				},
			}, nil)
			mock.DialBpfRecorderReturns(nil, nil)
			mock.SyscallsForProfileReturns(&bpfrecorderapi.SyscallsResponse{
				Syscalls: []string{"read"},
				GoArch:   runtime.GOARCH,
			}, nil)
			mock.ClientGetCalls(func(
				_ context.Context,
				_ client.Client,
				key types.NamespacedName,
				obj client.Object,
			) error {
				switch recordingResult := obj.(type) {
				case *recordingapi.ProfileRecording:
					require.Equal(t, client.ObjectKeyFromObject(recording), key)
					recording.DeepCopyInto(recordingResult)

					return nil
				default:
					t.Fatalf("unexpected ClientGet for %T", obj)

					return nil
				}
			})

			createdName := ""

			mock.CreateOrUpdateCalls(func(
				_ context.Context,
				_ client.Client,
				obj client.Object,
				mutate controllerutil.MutateFn,
			) (controllerutil.OperationResult, error) {
				createdName = obj.GetName()

				return controllerutil.OperationResultCreated, mutate()
			})

			sut := &RecorderReconciler{
				impl:   mock,
				client: kubeClient,
				log:    logr.Discard(),
				record: events.NewFakeRecorder(10),
			}
			err := sut.collectBpfProfiles(
				t.Context(),
				tc.replicaSuffix,
				types.NamespacedName{Name: tc.podName, Namespace: recording.Namespace},
				[]profileToCollect{{
					kind: recordingapi.ProfileRecordingKindSeccompProfile,
					name: "recording_container_nonce_timestamp",
				}},
				nil,
			)
			require.NoError(t, err)
			require.Equal(t, tc.expected, createdName)
			require.Equal(t, 1, mock.ResetSyscallsForProfileCallCount(),
				"the recorded data is dropped once the profile is stored")
		})
	}
}

func TestSchemeBuilder(t *testing.T) {
	t.Parallel()

	sut := NewController()
	assert.Equal(t, sut.SchemeBuilder(), recordingapi.SchemeBuilder)
}

func TestSetup(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*profilerecorderfakes.FakeImpl)
		assert  func(error)
	}{
		{ // Success
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.ClientGetCalls(func(
					ctx context.Context,
					c client.Client,
					key types.NamespacedName,
					obj client.Object,
				) error {
					node, ok := obj.(*corev1.Node)
					assert.True(t, ok)

					node.Status = corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{Type: corev1.NodeInternalIP, Address: "127.0.0.1"},
						},
					}

					return nil
				})
			},
			assert: func(err error) {
				assert.NoError(t, err)
			},
		},
		{ // NewClient fails
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.NewClientReturns(nil, errTest)
			},
			assert: func(err error) {
				assert.Error(t, err)
			},
		},
		{ // ClientGet fails
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.ClientGetReturns(errTest)
			},
			assert: func(err error) {
				assert.Error(t, err)
			},
		},
		{ // no node addresses
			prepare: func(mock *profilerecorderfakes.FakeImpl) {},
			assert: func(err error) {
				assert.Error(t, err)
			},
		},
		{ // NewControllerManagedBy fails
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.NewControllerManagedByReturns(errTest)
			},
			assert: func(err error) {
				assert.Error(t, err)
			},
		},
	} {
		mock := &profilerecorderfakes.FakeImpl{}
		tc.prepare(mock)

		sut := &RecorderReconciler{impl: mock}

		err := sut.Setup(t.Context(), nil, nil)
		tc.assert(err)
	}
}

// logsRecordingList returns a recording named "profile" that selects every pod
// and records every container with the log recorder.
func logsRecordingList(kind recordingapi.ProfileRecordingKind) *recordingapi.ProfileRecordingList {
	return &recordingapi.ProfileRecordingList{
		Items: []recordingapi.ProfileRecording{{
			ObjectMeta: metav1.ObjectMeta{Name: "profile"},
			Spec: recordingapi.ProfileRecordingSpec{
				Kind:        kind,
				Recorder:    recordingapi.ProfileRecorderLogs,
				PodSelector: &metav1.LabelSelector{},
			},
		}},
	}
}

// testAnnotationValue is a well-formed recording annotation: the recorded
// profile name is built from the first two fields, so it has to be fixed for an
// exact assertion.
const testAnnotationValue = "profile_ctr_4bbwm_1700000000"

// bpfApparmorRecordingList is bpfSeccompRecordingList for AppArmor profiles.
func bpfApparmorRecordingList() *recordingapi.ProfileRecordingList {
	return &recordingapi.ProfileRecordingList{
		Items: []recordingapi.ProfileRecording{{
			ObjectMeta: metav1.ObjectMeta{Name: "profile"},
			Spec: recordingapi.ProfileRecordingSpec{
				Kind:        recordingapi.ProfileRecordingKindAppArmorProfile,
				Recorder:    recordingapi.ProfileRecorderBpf,
				PodSelector: &metav1.LabelSelector{},
			},
		}},
	}
}

// bpfSeccompRecordingList returns a recording named "profile" that selects every
// pod and records every container with the BPF recorder.
func bpfSeccompRecordingList() *recordingapi.ProfileRecordingList {
	return &recordingapi.ProfileRecordingList{
		Items: []recordingapi.ProfileRecording{{
			ObjectMeta: metav1.ObjectMeta{Name: "profile"},
			Spec: recordingapi.ProfileRecordingSpec{
				Kind:        recordingapi.ProfileRecordingKindSeccompProfile,
				Recorder:    recordingapi.ProfileRecorderBpf,
				PodSelector: &metav1.LabelSelector{},
			},
		}},
	}
}

func TestReconcile(t *testing.T) {
	t.Parallel()

	testRequest := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "namespace",
			Name:      "name",
		},
	}

	for _, tc := range []struct {
		prepare func(*RecorderReconciler, *profilerecorderfakes.FakeImpl)
		assert  func(*RecorderReconciler, error)
	}{
		{ // Success phase pending no annotations
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NoError(t, err)
			},
		},
		{ // success pod not found
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(nil, kerrors.NewNotFound(schema.GroupResource{}, ""))
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NoError(t, err)
			},
		},
		{
			// seccomp BPF success record
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey + "ctr": testAnnotationValue,
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfSeccompRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				require.NoError(t, err)

				v, ok := sut.podsToWatch.Load(testRequest.String())
				assert.True(t, ok)
				pod, ok := v.(podToWatch)
				assert.True(t, ok)
				assert.Equal(t, recordingapi.ProfileRecorderBpf, pod.recorder)
				assert.Len(t, pod.profiles, 1)
				assert.Equal(t, recordingapi.ProfileRecordingKindSeccompProfile, pod.profiles[0].kind)
				assert.Equal(t, testAnnotationValue, pod.profiles[0].name)
				// already tracking
				_, retryErr := sut.Reconcile(t.Context(), testRequest)
				assert.NoError(t, retryErr)
			},
		},
		{
			// A trace annotation that no ProfileRecording asks for must not
			// start a recording: the annotation is attacker controlled in any
			// namespace where the recording webhook does not run.
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				value := fmt.Sprintf("spoofed_ctr_4bbwm_%d", time.Now().Unix())
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey + "ctr": value,
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				// Only an unrelated recording exists.
				mock.ListRecordingsReturns(bpfSeccompRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				require.NoError(t, err)

				_, ok := sut.podsToWatch.Load(testRequest.String())
				assert.False(t, ok, "an unauthorized annotation must not be recorded")
			},
		},
		{ // seccomp BPF success collect
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_4bbwm_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.SyscallsForProfileReturns(
					&bpfrecorderapi.SyscallsResponse{
						Syscalls: []string{"prctl", "mkdir"},
						GoArch:   runtime.GOARCH,
					}, nil,
				)
				mock.CreateOrUpdateCalls(func(
					ctx context.Context,
					c client.Client,
					obj client.Object,
					f controllerutil.MutateFn,
				) (controllerutil.OperationResult, error) {
					err := f()
					assert.NoError(t, err)

					return "", nil
				})
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NoError(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// seccomp BPF GoArchToSeccompArch fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.SyscallsForProfileReturns(
					&bpfrecorderapi.SyscallsResponse{
						Syscalls: []string{"prctl", "mkdir"},
						GoArch:   runtime.GOARCH,
					}, nil,
				)
				mock.GoArchToSeccompArchReturns("", errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// seccomp BPF CreateOrUpdate fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.SyscallsForProfileReturns(
					&bpfrecorderapi.SyscallsResponse{
						Syscalls: []string{"prctl", "mkdir"},
						GoArch:   runtime.GOARCH,
					}, nil,
				)
				mock.CreateOrUpdateReturns("", errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// seccomp BPF DialBpfRecorder fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // seccomp BPF DialBpfRecorder fails on StopBpfRecorder
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.SyscallsForProfileReturns(
					&bpfrecorderapi.SyscallsResponse{
						Syscalls: []string{"prctl", "mkdir"},
						GoArch:   runtime.GOARCH,
					}, nil,
				)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.StopBpfRecorderReturns(errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // seccomp BPF invalid profile name
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				const profileName = "invalid"

				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.SyscallsForProfileReturns(
					&bpfrecorderapi.SyscallsResponse{
						Syscalls: []string{"prctl", "mkdir"},
						GoArch:   runtime.GOARCH,
					}, nil,
				)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{
			// seccomp BPF SyscallsForProfile returns not found
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_4bbwm_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.SyscallsForProfileReturns(nil, bpfrecorder.ErrNotFound)
				mock.StopBpfRecorderReturns(nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NoError(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// seccomp BPF SyscallsForProfile fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.SyscallsForProfileReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // seccomp BPF DialBpfRecorder fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfSeccompRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// seccomp BPF StartBpfRecorder fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfSeccompRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.StartBpfRecorderReturns(errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // seccomp BPF GetSPOD fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfSeccompRecordingList(), nil)
				mock.GetSPODReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // seccomp BPF not enabled
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfSeccompRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: new(bool)}},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // seccomp BPF nil (defaults to disabled)
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfSeccompRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{}},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{
			// apparmor BPF success record
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfApparmorRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				require.NoError(t, err)

				v, ok := sut.podsToWatch.Load(testRequest.String())
				assert.True(t, ok)
				pod, ok := v.(podToWatch)
				assert.True(t, ok)
				assert.Equal(t, recordingapi.ProfileRecorderBpf, pod.recorder)
				assert.Len(t, pod.profiles, 1)
				assert.Equal(t, recordingapi.ProfileRecordingKindAppArmorProfile, pod.profiles[0].kind)
				assert.Regexp(t, `^profile_ctr_4bbwm_\d+$`, pod.profiles[0].name)
				// already tracking
				_, retryErr := sut.Reconcile(t.Context(), testRequest)
				assert.NoError(t, retryErr)
			},
		},
		{ // apparmor BPF success collect
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_apparmor_%d", time.Now().Unix())
				pod := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindAppArmorProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), pod)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.ApparmorForProfileReturns(
					&bpfrecorderapi.ApparmorResponse{
						Files: &bpfrecorderapi.ApparmorResponse_Files{
							AllowedExecutables: []string{"/usr/bin/test"},
						},
						Socket: &bpfrecorderapi.ApparmorResponse_Socket{
							UseTcp: true,
						},
						Capabilities: []string{"test-cap"},
					}, nil,
				)
				mock.CreateOrUpdateCalls(func(
					ctx context.Context,
					c client.Client,
					obj client.Object,
					f controllerutil.MutateFn,
				) (controllerutil.OperationResult, error) {
					err := f()
					assert.NoError(t, err)

					return "", nil
				})
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NoError(t, err)
			},
		},
		{ // apparmor BPF CreateOrUpdate fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindAppArmorProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.ApparmorForProfileReturns(
					&bpfrecorderapi.ApparmorResponse{
						Files: &bpfrecorderapi.ApparmorResponse_Files{
							AllowedExecutables: []string{"/usr/bin/test"},
						},
						Socket: &bpfrecorderapi.ApparmorResponse_Socket{
							UseTcp: true,
						},
						Capabilities: []string{"test-cap"},
					}, nil,
				)
				mock.CreateOrUpdateReturns("", errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// apparmor BPF DialBpfRecorder fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindAppArmorProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // apparmor BPF DialBpfRecorder fails on StopBpfRecorder
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindAppArmorProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.ApparmorForProfileReturns(
					&bpfrecorderapi.ApparmorResponse{
						Files: &bpfrecorderapi.ApparmorResponse_Files{
							AllowedExecutables: []string{"/usr/bin/test"},
						},
						Socket: &bpfrecorderapi.ApparmorResponse_Socket{
							UseTcp: true,
						},
						Capabilities: []string{"test-cap"},
					}, nil,
				)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.StopBpfRecorderReturns(errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // apparmor BPF invalid profile name
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				const profileName = "invalid"

				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindAppArmorProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.ApparmorForProfileReturns(
					&bpfrecorderapi.ApparmorResponse{
						Files: &bpfrecorderapi.ApparmorResponse_Files{
							AllowedExecutables: []string{"/usr/bin/test"},
						},
						Socket: &bpfrecorderapi.ApparmorResponse_Socket{
							UseTcp: true,
						},
						Capabilities: []string{"test-cap"},
					}, nil,
				)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{
			// apparmor BPF ApparmorForProfile returns not found
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_4bbwm_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindAppArmorProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.ApparmorForProfileReturns(nil, bpfrecorder.ErrNotFound)
				mock.StopBpfRecorderReturns(nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NoError(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// apparmor BPF ApparmorForProfiles fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindAppArmorProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.ApparmorForProfileReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // apparmor BPF DialBpfRecorder fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfApparmorRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// apparmor BPF StartBpfRecorder fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfApparmorRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
				}, nil)
				mock.DialBpfRecorderReturns(nil, nil)
				mock.StartBpfRecorderReturns(errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // apparmor BPF GetSPOD fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfApparmorRecordingList(), nil)
				mock.GetSPODReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // seccomp BPF not enabled
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfApparmorRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: new(bool)}},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // apparmor BPF nil (defaults to disabled)
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.ApparmorProfileRecordBpfAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(bpfApparmorRecordingList(), nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{}},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // parseBpfAnnotations failed
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: "",
						},
					},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NoError(t, err)
			},
		},
		{ // parseLogAnnotations failed
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: "",
						},
					},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NoError(t, err)
			},
		},
		{ // failure GetPod (error reading pod)
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// log seccomp success record
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(logsRecordingList(recordingapi.ProfileRecordingKindSeccompProfile), nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				require.NoError(t, err)

				v, ok := sut.podsToWatch.Load(testRequest.String())
				assert.True(t, ok)
				pod, ok := v.(podToWatch)
				assert.True(t, ok)
				assert.Equal(t, recordingapi.ProfileRecorderLogs, pod.recorder)
				assert.Len(t, pod.profiles, 1)
				assert.Equal(t, recordingapi.ProfileRecordingKindSeccompProfile, pod.profiles[0].kind)
				assert.Regexp(t, `^profile_ctr_4bbwm_\d+$`, pod.profiles[0].name)
				// already tracking
				_, retryErr := sut.Reconcile(t.Context(), testRequest)
				assert.NoError(t, retryErr)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// log seccomp success record
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SelinuxProfileRecordLogsAnnotationKey: fmt.Sprintf("profile_ctr_4bbwm_%d", time.Now().Unix()),
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "ctr"}},
					},
				}, nil)
				mock.ListRecordingsReturns(logsRecordingList(recordingapi.ProfileRecordingKindSelinuxProfile), nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				require.NoError(t, err)

				v, ok := sut.podsToWatch.Load(testRequest.String())
				assert.True(t, ok)
				pod, ok := v.(podToWatch)
				assert.True(t, ok)
				assert.Equal(t, recordingapi.ProfileRecorderLogs, pod.recorder)
				assert.Len(t, pod.profiles, 1)
				assert.Equal(t, recordingapi.ProfileRecordingKindSelinuxProfile, pod.profiles[0].kind)
				assert.Regexp(t, `^profile_ctr_4bbwm_\d+$`, pod.profiles[0].name)
				// already tracking
				_, retryErr := sut.Reconcile(t.Context(), testRequest)
				assert.NoError(t, retryErr)
			},
		},
		{ // logs seccomp success collect
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_4bbwm_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
				mock.SyscallsReturns(
					&enricherapi.SyscallsResponse{GoArch: runtime.GOARCH}, nil,
				)
				mock.CreateOrUpdateCalls(func(
					ctx context.Context,
					c client.Client,
					obj client.Object,
					f controllerutil.MutateFn,
				) (controllerutil.OperationResult, error) {
					err := f()
					assert.NoError(t, err)

					return "", nil
				})
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NoError(t, err)
			},
		},
		{ // logs seccomp failed ResetSyscalls
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
				mock.SyscallsReturns(
					&enricherapi.SyscallsResponse{GoArch: runtime.GOARCH}, nil,
				)
				mock.ResetSyscallsReturns(errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// logs seccomp failed CreateOrUpdate
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
				mock.SyscallsReturns(
					&enricherapi.SyscallsResponse{GoArch: runtime.GOARCH}, nil,
				)
				mock.CreateOrUpdateReturns("", errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// logs seccomp failed GoArchToSeccompArch
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
				mock.SyscallsReturns(
					&enricherapi.SyscallsResponse{GoArch: runtime.GOARCH}, nil,
				)
				mock.GoArchToSeccompArchReturns("", errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// logs seccomp failed Syscalls
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
				mock.SyscallsReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // logs seccomp failed unknown kind
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: "wrong",
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.DialEnricherReturns(nil, nil)
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // logs seccomp wrong profile name
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				const profileName = "profile"

				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// logs seccomp DialEnricher fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // logs seccomp EnableLogEnricher false
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: new(bool)}},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // logs seccomp EnableLogEnricher nil (defaults to disabled)
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{}},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // logs seccomp failed GetSPOD
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // logs selinux success collect
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_4bbwm_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSelinuxProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SelinuxProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
				mock.AvcsReturns(&enricherapi.AvcResponse{
					Avc: []*enricherapi.AvcResponse_SelinuxAvc{
						{
							Tclass:   "class",
							Tcontext: "0:1:2",
						},
					},
				}, nil)
				mock.CreateOrUpdateCalls(func(
					ctx context.Context,
					c client.Client,
					obj client.Object,
					f controllerutil.MutateFn,
				) (controllerutil.OperationResult, error) {
					err := f()
					assert.NoError(t, err)

					return "", nil
				})
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NoError(t, err)
			},
		},
		{ // logs selinux failed ResetAvcs
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSelinuxProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SelinuxProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
				mock.ResetAvcsReturns(errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // logs selinux failed CreateOrUpdate
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSelinuxProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SelinuxProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
				mock.CreateOrUpdateReturns("", errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ // logs selinux failed formatSelinuxProfile
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSelinuxProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SelinuxProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
				mock.AvcsReturns(&enricherapi.AvcResponse{
					Avc: []*enricherapi.AvcResponse_SelinuxAvc{
						{Tcontext: "wrong"},
					},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			// logs selinux failed Avcs
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile_replica-123_%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderLogs,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSelinuxProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SelinuxProfileRecordLogsAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: ptrTrue()}},
				}, nil)
				mock.DialEnricherReturns(nil, nil)
				mock.AvcsReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Error(t, err)
			},
		},
	} {
		mock := &profilerecorderfakes.FakeImpl{}
		sut := &RecorderReconciler{
			impl:   mock,
			log:    logr.Discard(),
			record: events.NewFakeRecorder(10),
		}
		tc.prepare(sut, mock)

		_, err := sut.Reconcile(t.Context(), testRequest)
		tc.assert(sut, err)
	}
}

func TestIsPodOnLocalNode(t *testing.T) {
	t.Parallel()

	const ip = "127.0.0.1"

	for _, tc := range []struct {
		prepare func(*RecorderReconciler) apiruntime.Object
		assert  func(bool)
	}{
		{ // success
			prepare: func(sut *RecorderReconciler) apiruntime.Object {
				sut.nodeAddresses = []string{ip}

				return &corev1.Pod{Status: corev1.PodStatus{HostIP: ip}}
			},
			assert: func(res bool) {
				assert.True(t, res)
			},
		},
		{ // no pod
			prepare: func(sut *RecorderReconciler) apiruntime.Object {
				return &corev1.PodList{}
			},
			assert: func(res bool) {
				assert.False(t, res)
			},
		},
		{ // not found
			prepare: func(sut *RecorderReconciler) apiruntime.Object {
				return &corev1.Pod{Status: corev1.PodStatus{HostIP: ip}}
			},
			assert: func(res bool) {
				assert.False(t, res)
			},
		},
	} {
		sut := &RecorderReconciler{}
		obj := tc.prepare(sut)

		res := sut.isPodOnLocalNode(obj)
		tc.assert(res)
	}
}

func TestIsPodWithTraceAnnotation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*RecorderReconciler) apiruntime.Object
		assert  func(bool)
	}{
		{ // success selinux logs
			prepare: func(sut *RecorderReconciler) apiruntime.Object {
				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						config.SelinuxProfileRecordLogsAnnotationKey: "",
					},
				}}
			},
			assert: func(res bool) {
				assert.True(t, res)
			},
		},
		{ // success seccomp logs
			prepare: func(sut *RecorderReconciler) apiruntime.Object {
				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						config.SeccompProfileRecordLogsAnnotationKey: "",
					},
				}}
			},
			assert: func(res bool) {
				assert.True(t, res)
			},
		},
		{ // success seccomp bpf
			prepare: func(sut *RecorderReconciler) apiruntime.Object {
				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						config.SeccompProfileRecordBpfAnnotationKey: "",
					},
				}}
			},
			assert: func(res bool) {
				assert.True(t, res)
			},
		},
		{ // success seccomp bpf
			prepare: func(sut *RecorderReconciler) apiruntime.Object {
				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						config.ApparmorProfileRecordBpfAnnotationKey: "",
					},
				}}
			},
			assert: func(res bool) {
				assert.True(t, res)
			},
		},
		{ // no pod
			prepare: func(sut *RecorderReconciler) apiruntime.Object {
				return &corev1.PodList{}
			},
			assert: func(res bool) {
				assert.False(t, res)
			},
		},
		{ // not found
			prepare: func(sut *RecorderReconciler) apiruntime.Object {
				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				}}
			},
			assert: func(res bool) {
				assert.False(t, res)
			},
		},
	} {
		sut := &RecorderReconciler{}
		obj := tc.prepare(sut)

		res := sut.isPodWithTraceAnnotation(obj)
		tc.assert(res)
	}
}

// The UDP branch used to test GetUseTcp(), so a UDP-only workload produced an
// AppArmor profile with no network rules at all while a TCP-only workload was
// granted UDP it never used.
func TestGenerateAppArmorProfileAbstractProtocols(t *testing.T) {
	t.Parallel()

	enabled := true

	for name, tc := range map[string]struct {
		socket   *bpfrecorderapi.ApparmorResponse_Socket
		wantRaw  *bool
		wantTCP  *bool
		wantUDP  *bool
		wantNone bool
	}{
		"udp only": {
			socket:  &bpfrecorderapi.ApparmorResponse_Socket{UseUdp: true},
			wantUDP: &enabled,
		},
		"tcp only": {
			socket:  &bpfrecorderapi.ApparmorResponse_Socket{UseTcp: true},
			wantTCP: &enabled,
		},
		"tcp and udp": {
			socket:  &bpfrecorderapi.ApparmorResponse_Socket{UseTcp: true, UseUdp: true},
			wantTCP: &enabled,
			wantUDP: &enabled,
		},
		"raw only": {
			socket:  &bpfrecorderapi.ApparmorResponse_Socket{UseRaw: true},
			wantRaw: &enabled,
		},
		"no socket usage": {
			socket:   &bpfrecorderapi.ApparmorResponse_Socket{},
			wantNone: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := &RecorderReconciler{}
			abstract := r.generateAppArmorProfileAbstract(
				&bpfrecorderapi.ApparmorResponse{Socket: tc.socket},
			)

			if tc.wantNone {
				require.Nil(t, abstract.Network)

				return
			}

			require.NotNil(t, abstract.Network)
			require.Equal(t, tc.wantRaw, abstract.Network.AllowRaw)

			if tc.wantTCP == nil && tc.wantUDP == nil {
				require.Nil(t, abstract.Network.Protocols)

				return
			}

			require.NotNil(t, abstract.Network.Protocols)
			require.Equal(t, tc.wantTCP, abstract.Network.Protocols.AllowTCP)
			require.Equal(t, tc.wantUDP, abstract.Network.Protocols.AllowUDP)
		})
	}
}

// TestReconcileDoesNotArmRecorderWithoutAuthorization pins down the ordering the
// authorization gate depends on: nothing with a side effect may run before a
// pod's recording annotations have been matched against a ProfileRecording.
// Arming the node's BPF recorder is such a side effect, and it used to be
// reachable from a pod annotation alone.
func TestReconcileDoesNotArmRecorderWithoutAuthorization(t *testing.T) {
	t.Parallel()

	testRequest := reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "namespace", Name: "name"},
	}

	for _, tc := range []struct {
		name       string
		annotation string
		recordings *recordingapi.ProfileRecordingList
	}{
		{
			// A malformed value must not be passed through: doing so makes the
			// profile list non-empty, which arms the recorder.
			name:       "malformed annotation",
			annotation: "junk",
			recordings: &recordingapi.ProfileRecordingList{},
		},
		{
			name:       "no matching profile recording",
			annotation: "other-recording_ctr_4bbwm_1700000000",
			recordings: &recordingapi.ProfileRecordingList{},
		},
		{
			name:       "recording exists but selects no pods",
			annotation: testAnnotationValue,
			recordings: &recordingapi.ProfileRecordingList{
				Items: []recordingapi.ProfileRecording{{
					ObjectMeta: metav1.ObjectMeta{Name: "profile"},
					Spec: recordingapi.ProfileRecordingSpec{
						Kind:     recordingapi.ProfileRecordingKindSeccompProfile,
						Recorder: recordingapi.ProfileRecorderBpf,
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "something-else"},
						},
					},
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &profilerecorderfakes.FakeImpl{}
			mock.GetPodReturns(&corev1.Pod{
				Status: corev1.PodStatus{Phase: corev1.PodPending},
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						config.SeccompProfileRecordBpfAnnotationKey: tc.annotation,
					},
				},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "ctr"}}},
			}, nil)
			mock.ListRecordingsReturns(tc.recordings, nil)
			mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
				Spec: spodapi.SPODSpec{
					Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()},
				},
			}, nil)

			sut := &RecorderReconciler{
				impl:   mock,
				log:    logr.Discard(),
				record: events.NewFakeRecorder(10),
			}

			_, err := sut.Reconcile(t.Context(), testRequest)
			require.NoError(t, err)

			assert.Zero(t, mock.DialBpfRecorderCallCount(), "the recorder must not be dialed")
			assert.Zero(t, mock.StartBpfRecorderCallCount(), "the recorder must not be armed")

			_, tracked := sut.podsToWatch.Load(testRequest.String())
			assert.False(t, tracked, "the pod must not be watched")
		})
	}
}

// TestReconcileRecordsRunningPod asserts that a pod first seen when it already
// runs, for example after the daemon restarted, is still recorded.
func TestReconcileRecordsRunningPod(t *testing.T) {
	t.Parallel()

	request := reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "namespace", Name: "name"},
	}

	mock := &profilerecorderfakes.FakeImpl{}
	mock.GetPodReturns(&corev1.Pod{
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "ctr": testAnnotationValue,
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "ctr"}}},
	}, nil)

	recordings := bpfSeccompRecordingList()
	recordings.Items[0].Spec.MergeStrategy = recordingapi.ProfileMergeContainers
	recordings.Items[0].Spec.DisableProfileAfterRecording = true
	mock.ListRecordingsReturns(recordings, nil)
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
	}, nil)

	recorder := events.NewFakeRecorder(10)
	sut := &RecorderReconciler{impl: mock, log: logr.Discard(), record: recorder}

	_, err := sut.Reconcile(t.Context(), request)
	require.NoError(t, err)

	value, ok := sut.podsToWatch.Load(request.String())
	require.True(t, ok)

	watched, ok := value.(podToWatch)
	require.True(t, ok)
	require.Equal(t, recordingState{partial: true, disable: true}, watched.recordings["profile"])
	require.Equal(t, 1, mock.StartBpfRecorderCallCount())

	var warned bool

	for len(recorder.Events) > 0 {
		if strings.Contains(<-recorder.Events, reasonRecordingIncomplete) {
			warned = true
		}
	}

	require.True(t, warned, "the profile may be incomplete, which has to be reported")
}

// TestResolveProfileTargetRecordingGone covers what happens when the
// ProfileRecording disappears while its pods are still being collected. With
// nothing known about it the pod can never be collected. Otherwise the state
// captured when the pod started being recorded is used, and a partial profile
// is merged right away, as nothing would merge it any more.
func TestResolveProfileTargetRecordingGone(t *testing.T) {
	t.Parallel()

	mock := &profilerecorderfakes.FakeImpl{}
	mock.ClientGetReturns(kerrors.NewNotFound(schema.GroupResource{}, "recording"))

	sut := &RecorderReconciler{impl: mock, log: logr.Discard()}
	parsed := &parsedAnnotation{profileName: "recording", cntName: "ctr"}
	podName := types.NamespacedName{Name: "pod", Namespace: "ns"}

	_, err := sut.resolveProfileTarget(t.Context(), parsed, "", podName, nil)
	require.ErrorIs(t, err, errRecordingGone)
	require.True(t, unrecordable(err), "the reconciler must release the pod for this error")

	target, err := sut.resolveProfileTarget(t.Context(), parsed, "abcde", podName,
		map[string]recordingState{"recording": {partial: true, disable: true}})
	require.NoError(t, err)
	require.True(t, target.merge)
	require.True(t, target.state.disable)
	require.Nil(t, target.recording)
	require.Equal(t, "recording-ctr", target.name.Name)
	require.NotContains(t, target.labels, profilebase.ProfilePartialLabel)

	target, err = sut.resolveProfileTarget(t.Context(), parsed, "abcde", podName,
		map[string]recordingState{"recording": {}})
	require.NoError(t, err)
	require.False(t, target.merge)
	require.Equal(t, "recording-ctr-abcde", target.name.Name)
}

func TestResolveProfileTarget(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		strategy    recordingapi.ProfileMergeStrategy
		deleting    bool
		finalizer   bool
		wantPartial bool
		wantMerge   bool
		wantName    string
	}{
		{
			name:     "no merging",
			strategy: recordingapi.ProfileMergeNone,
			wantName: "recording-ctr",
		},
		{
			name:        "merge containers",
			strategy:    recordingapi.ProfileMergeContainers,
			wantPartial: true,
			wantName:    "recording-ctr-pod",
		},
		{
			// The merger may be done already, so a partial profile would be
			// left behind.
			name:      "merge containers of a recording being deleted",
			strategy:  recordingapi.ProfileMergeContainers,
			deleting:  true,
			finalizer: true,
			wantMerge: true,
			wantName:  "recording-ctr",
		},
		{
			name:      "merge containers of a recording which does not wait for them",
			strategy:  recordingapi.ProfileMergeContainers,
			deleting:  true,
			wantMerge: true,
			wantName:  "recording-ctr",
		},
		{
			name:     "no merging of a recording being deleted",
			strategy: recordingapi.ProfileMergeNone,
			deleting: true,
			wantName: "recording-ctr",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &profilerecorderfakes.FakeImpl{}
			mock.ClientGetCalls(func(
				_ context.Context, _ client.Client,
				_ client.ObjectKey, obj client.Object,
			) error {
				recording, ok := obj.(*recordingapi.ProfileRecording)
				require.True(t, ok)

				recording.Name = "recording"
				recording.Spec.MergeStrategy = tc.strategy

				if tc.deleting {
					recording.DeletionTimestamp = &metav1.Time{Time: time.Now()}
				}

				if tc.finalizer {
					recording.Finalizers = []string{recordingapi.RecordingHasUnmergedProfiles}
				}

				return nil
			})

			sut := &RecorderReconciler{impl: mock, log: logr.Discard()}

			target, err := sut.resolveProfileTarget(
				t.Context(),
				&parsedAnnotation{profileName: "recording", cntName: "ctr"},
				"",
				types.NamespacedName{Name: "pod", Namespace: "ns"},
				nil,
			)
			require.NoError(t, err)
			require.Equal(t, tc.wantName, target.name.Name)
			require.Equal(t, tc.wantMerge, target.merge)
			require.Equal(t, "recording", target.labels[recordingapi.ProfileToRecordingLabel])
			require.Equal(t, "ns", target.labels[recordingapi.ProfileToRecordingNamespaceLabel])
			require.Equal(t, "ctr", target.labels[recordingapi.ProfileToContainerLabel])

			_, partial := target.labels[profilebase.ProfilePartialLabel]
			require.Equal(t, tc.wantPartial, partial)
		})
	}
}

func TestResolveProfileTargetInvalidName(t *testing.T) {
	t.Parallel()

	sut := &RecorderReconciler{impl: &profilerecorderfakes.FakeImpl{}, log: logr.Discard()}

	_, err := sut.resolveProfileTarget(
		t.Context(),
		&parsedAnnotation{profileName: "Invalid.Name", cntName: "ctr"},
		"",
		types.NamespacedName{Name: "pod", Namespace: "ns"},
		nil,
	)
	require.ErrorIs(t, err, errNameNotValid)
}

// TestReleaseUnrecordablePod covers the cleanup for a pod that can never be
// collected: without it the watch entry leaks and, for the BPF recorder, the
// node stays armed for the lifetime of the daemon.
func TestReleaseUnrecordablePod(t *testing.T) {
	t.Parallel()

	podName := types.NamespacedName{Namespace: "ns", Name: "pod"}

	t.Run("bpf recorder is stopped", func(t *testing.T) {
		t.Parallel()

		mock := &profilerecorderfakes.FakeImpl{}
		mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
			Spec: spodapi.SPODSpec{
				Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()},
			},
		}, nil)

		sut := &RecorderReconciler{impl: mock, log: logr.Discard()}
		sut.podsToWatch.Store(podName.String(), podToWatch{
			recorder: recordingapi.ProfileRecorderBpf,
			profiles: []profileToCollect{
				{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "seccomp"},
				{kind: recordingapi.ProfileRecordingKindAppArmorProfile, name: "apparmor"},
			},
		})

		sut.releaseUnrecordablePod(t.Context(), podName)

		_, tracked := sut.podsToWatch.Load(podName.String())
		require.False(t, tracked)
		require.Equal(t, 1, mock.StopBpfRecorderCallCount())

		// The recorded data would otherwise stay until the recorder stops.
		require.Equal(t, 1, mock.ResetSyscallsForProfileCallCount())
		_, _, req := mock.ResetSyscallsForProfileArgsForCall(0)
		require.Equal(t, "seccomp", req.GetName())
		require.Equal(t, 1, mock.ResetApparmorForProfileCallCount())
	})

	t.Run("log recorder drops the enricher data", func(t *testing.T) {
		t.Parallel()

		mock := &profilerecorderfakes.FakeImpl{}
		sut := &RecorderReconciler{impl: mock, log: logr.Discard()}
		sut.podsToWatch.Store(podName.String(), podToWatch{
			recorder: recordingapi.ProfileRecorderLogs,
			profiles: []profileToCollect{
				{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "seccomp"},
				{kind: recordingapi.ProfileRecordingKindSelinuxProfile, name: "selinux"},
			},
		})

		sut.releaseUnrecordablePod(t.Context(), podName)

		_, tracked := sut.podsToWatch.Load(podName.String())
		require.False(t, tracked)
		require.Zero(t, mock.StopBpfRecorderCallCount())

		require.Equal(t, 1, mock.ResetSyscallsCallCount())
		_, _, syscallsReq := mock.ResetSyscallsArgsForCall(0)
		require.Equal(t, "seccomp", syscallsReq.GetProfile())
		require.Equal(t, 1, mock.ResetAvcsCallCount())
		_, _, avcReq := mock.ResetAvcsArgsForCall(0)
		require.Equal(t, "selinux", avcReq.GetProfile())
	})

	t.Run("unknown pod is a no-op", func(t *testing.T) {
		t.Parallel()

		mock := &profilerecorderfakes.FakeImpl{}
		sut := &RecorderReconciler{impl: mock, log: logr.Discard()}

		sut.releaseUnrecordablePod(t.Context(), podName)

		require.Zero(t, mock.StopBpfRecorderCallCount())
	})
}

func TestHoldRecordingSkipsDeletedRecording(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		deleting      bool
		wantFinalizer bool
	}{
		{name: "active recording", wantFinalizer: true},
		{name: "recording being deleted", deleting: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recording := &recordingapi.ProfileRecording{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "recording",
					Namespace:  "ns",
					Finalizers: []string{"other"},
				},
			}
			if tc.deleting {
				recording.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			}

			scheme := apiruntime.NewScheme()
			require.NoError(t, recordingapi.AddToScheme(scheme))
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(recording).Build()

			stored := &recordingapi.ProfileRecording{}
			require.NoError(t, kubeClient.Get(
				t.Context(), client.ObjectKeyFromObject(recording), stored,
			))

			sut := &RecorderReconciler{client: kubeClient, log: logr.Discard()}

			require.NoError(t, sut.holdRecording(t.Context(), &profileTarget{
				state:     recordingState{partial: true},
				recording: stored,
			}))

			got := &recordingapi.ProfileRecording{}
			require.NoError(t, kubeClient.Get(
				t.Context(), client.ObjectKeyFromObject(recording), got,
			))
			require.Equal(t, tc.wantFinalizer,
				controllerutil.ContainsFinalizer(got, recordingapi.RecordingHasUnmergedProfiles))
		})
	}
}

// TestCollectBpfProfileKeepsDataOnFailure asserts that the recorded data is
// only dropped once the profile is stored, so that the retry has it.
func TestCollectBpfProfileKeepsDataOnFailure(t *testing.T) {
	t.Parallel()

	recording := &recordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: "recording", Namespace: "ns"},
	}

	mock := &profilerecorderfakes.FakeImpl{}
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()},
		},
	}, nil)
	mock.ApparmorForProfileReturns(&bpfrecorderapi.ApparmorResponse{
		Capabilities: []string{"net_raw"},
	}, nil)
	mock.ClientGetCalls(func(
		_ context.Context, _ client.Client, _ types.NamespacedName, obj client.Object,
	) error {
		recordingResult, ok := obj.(*recordingapi.ProfileRecording)
		require.True(t, ok)
		recording.DeepCopyInto(recordingResult)

		return nil
	})
	mock.CreateOrUpdateReturnsOnCall(0, "", errTest)
	mock.CreateOrUpdateReturnsOnCall(1, controllerutil.OperationResultCreated, nil)

	sut := &RecorderReconciler{
		impl:   mock,
		log:    logr.Discard(),
		record: events.NewFakeRecorder(10),
	}

	profiles := []profileToCollect{{
		kind: recordingapi.ProfileRecordingKindAppArmorProfile,
		name: "recording_container_nonce_timestamp",
	}}
	podName := types.NamespacedName{Name: "pod", Namespace: recording.Namespace}

	err := sut.collectBpfProfiles(t.Context(), "", podName, profiles, nil)
	require.ErrorIs(t, err, errTest)
	require.Zero(t, mock.ResetApparmorForProfileCallCount())
	require.Zero(t, mock.StopBpfRecorderCallCount())

	err = sut.collectBpfProfiles(t.Context(), "", podName, profiles, nil)
	require.NoError(t, err)
	require.Equal(t, 1, mock.ResetApparmorForProfileCallCount())
	require.Equal(t, 1, mock.StopBpfRecorderCallCount())
}

// TestStoreProfileMergesProfileOfRecordingGone asserts that a partial profile
// collected after its recording is gone is merged into the final profile
// instead of being left behind unmerged.
func TestStoreProfileMergesProfileOfRecordingGone(t *testing.T) {
	t.Parallel()

	scheme := apiruntime.NewScheme()
	require.NoError(t, seccompprofileapi.AddToScheme(scheme))
	require.NoError(t, recordingapi.AddToScheme(scheme))

	labels := map[string]string{
		recordingapi.ProfileToRecordingLabel:          "recording",
		recordingapi.ProfileToRecordingNamespaceLabel: "ns",
		recordingapi.ProfileToContainerLabel:          "ctr",
	}

	merged := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "recording-ctr", Labels: labels},
		Spec: seccompprofileapi.SeccompProfileSpec{
			DefaultAction: seccompprofileapi.ActErrno,
			Syscalls: []seccompprofileapi.Syscall{{
				Action: seccompprofileapi.ActAllow,
				Names:  []string{"read"},
			}},
		},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(merged).Build()

	mock := &profilerecorderfakes.FakeImpl{}
	mock.ClientGetCalls(func(
		ctx context.Context, c client.Client, key types.NamespacedName, obj client.Object,
	) error {
		return c.Get(ctx, key, obj)
	})
	mock.CreateOrUpdateCalls(controllerutil.CreateOrUpdate)

	sut := &RecorderReconciler{
		impl:   mock,
		client: kubeClient,
		log:    logr.Discard(),
		record: events.NewFakeRecorder(10),
	}

	target, err := sut.resolveProfileTarget(
		t.Context(),
		&parsedAnnotation{profileName: "recording", cntName: "ctr"},
		"",
		types.NamespacedName{Name: "pod", Namespace: "ns"},
		map[string]recordingState{"recording": {partial: true}},
	)
	require.NoError(t, err)
	require.True(t, target.merge)

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: target.name.Name, Labels: target.labels},
		Spec: seccompprofileapi.SeccompProfileSpec{
			DefaultAction: seccompprofileapi.ActErrno,
			Syscalls: []seccompprofileapi.Syscall{{
				Action: seccompprofileapi.ActAllow,
				Names:  []string{"write"},
			}},
		},
	}

	require.NoError(
		t,
		sut.storeProfile(t.Context(), target, profile, &profile.Spec.SpecBase, "seccomp"),
	)

	got := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKey{Name: "recording-ctr"}, got))

	var names []string
	for _, syscall := range got.Spec.Syscalls {
		names = append(names, syscall.Names...)
	}

	require.ElementsMatch(t, []string{"read", "write"}, names)
}

// TestCollectBpfProfileOfRecordingWhoseMergeFinished asserts that a partial
// profile collected while the recording is being deleted ends up merged, even
// when the merger already finished and nothing would merge it any more.
func TestCollectBpfProfileOfRecordingWhoseMergeFinished(t *testing.T) {
	t.Parallel()

	recording := &recordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "recording",
			Namespace:         "ns",
			Finalizers:        []string{recordingapi.RecordingHasUnmergedProfiles},
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
		},
		Spec: recordingapi.ProfileRecordingSpec{
			MergeStrategy: recordingapi.ProfileMergeContainers,
		},
	}

	scheme := apiruntime.NewScheme()
	require.NoError(t, recordingapi.AddToScheme(scheme))
	require.NoError(t, seccompprofileapi.AddToScheme(scheme))
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(recording).Build()

	mock := &profilerecorderfakes.FakeImpl{}
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()},
		},
	}, nil)
	mock.SyscallsForProfileReturns(&bpfrecorderapi.SyscallsResponse{
		Syscalls: []string{"read"},
		GoArch:   runtime.GOARCH,
	}, nil)
	mock.ClientGetCalls(func(
		ctx context.Context, c client.Client, key types.NamespacedName, obj client.Object,
	) error {
		return c.Get(ctx, key, obj)
	})
	mock.CreateOrUpdateCalls(controllerutil.CreateOrUpdate)

	sut := &RecorderReconciler{
		impl:   mock,
		client: kubeClient,
		log:    logr.Discard(),
		record: events.NewFakeRecorder(10),
	}

	require.NoError(t, sut.collectBpfProfiles(
		t.Context(),
		"",
		types.NamespacedName{Name: "pod", Namespace: recording.Namespace},
		[]profileToCollect{{
			kind: recordingapi.ProfileRecordingKindSeccompProfile,
			name: "recording_ctr_nonce_timestamp",
		}},
		nil,
	))

	profiles := &seccompprofileapi.SeccompProfileList{}
	require.NoError(t, kubeClient.List(t.Context(), profiles))
	require.Len(t, profiles.Items, 1)
	require.Equal(t, "recording-ctr", profiles.Items[0].Name)
	require.NotContains(t, profiles.Items[0].Labels, profilebase.ProfilePartialLabel)
}

// TestCollectBpfProfileRejected asserts that a profile the API server rejects
// for good is dropped instead of being retried forever, which would keep the
// node's recorder running.
func TestCollectBpfProfileRejected(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		rejection error
		attempts  int
	}{
		{rejection: kerrors.NewInvalid(schema.GroupKind{Kind: "SeccompProfile"}, "p", nil), attempts: 1},
		{rejection: kerrors.NewRequestEntityTooLargeError("too large"), attempts: 1},
		// A permission may not have been granted yet.
		{rejection: kerrors.NewForbidden(schema.GroupResource{}, "p", errTest), attempts: maxForbiddenAttempts},
	} {
		recording := &recordingapi.ProfileRecording{
			ObjectMeta: metav1.ObjectMeta{Name: "recording", Namespace: "ns"},
		}

		mock := &profilerecorderfakes.FakeImpl{}
		mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
			Spec: spodapi.SPODSpec{
				Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()},
			},
		}, nil)
		mock.SyscallsForProfileReturns(&bpfrecorderapi.SyscallsResponse{
			Syscalls: []string{"read"},
			GoArch:   runtime.GOARCH,
		}, nil)
		mock.ClientGetCalls(func(
			_ context.Context, _ client.Client, _ types.NamespacedName, obj client.Object,
		) error {
			recordingResult, ok := obj.(*recordingapi.ProfileRecording)
			require.True(t, ok)
			recording.DeepCopyInto(recordingResult)

			return nil
		})
		mock.CreateOrUpdateReturns("", tc.rejection)

		recorder := events.NewFakeRecorder(10)
		sut := &RecorderReconciler{impl: mock, log: logr.Discard(), record: recorder}

		for attempt := 1; attempt <= tc.attempts; attempt++ {
			err := sut.collectBpfProfiles(
				t.Context(),
				"",
				types.NamespacedName{Name: "pod", Namespace: recording.Namespace},
				[]profileToCollect{{
					kind: recordingapi.ProfileRecordingKindSeccompProfile,
					name: "recording_ctr_nonce_timestamp",
				}},
				nil,
			)
			require.Contains(t, <-recorder.Events, reasonProfileCreationFailed)

			if attempt < tc.attempts {
				require.Error(t, err)
				require.Zero(t, mock.ResetSyscallsForProfileCallCount())

				continue
			}

			require.NoError(t, err)
		}

		require.Equal(t, 1, mock.ResetSyscallsForProfileCallCount())
		require.Equal(t, 1, mock.StopBpfRecorderCallCount())
	}
}

// TestCollectBpfProfileRetriesTransientErrors asserts that other errors are
// still retried with the recorded data kept.
func TestCollectBpfProfileRetriesTransientErrors(t *testing.T) {
	t.Parallel()

	recording := &recordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: "recording", Namespace: "ns"},
	}

	mock := &profilerecorderfakes.FakeImpl{}
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()},
		},
	}, nil)
	mock.SyscallsForProfileReturns(&bpfrecorderapi.SyscallsResponse{
		Syscalls: []string{"read"},
		GoArch:   runtime.GOARCH,
	}, nil)
	mock.ClientGetCalls(func(
		_ context.Context, _ client.Client, _ types.NamespacedName, obj client.Object,
	) error {
		recordingResult, ok := obj.(*recordingapi.ProfileRecording)
		require.True(t, ok)
		recording.DeepCopyInto(recordingResult)

		return nil
	})
	mock.CreateOrUpdateReturns("", kerrors.NewServiceUnavailable("unavailable"))

	sut := &RecorderReconciler{impl: mock, log: logr.Discard(), record: events.NewFakeRecorder(10)}

	require.Error(t, sut.collectBpfProfiles(
		t.Context(),
		"",
		types.NamespacedName{Name: "pod", Namespace: recording.Namespace},
		[]profileToCollect{{
			kind: recordingapi.ProfileRecordingKindSeccompProfile,
			name: "recording_ctr_nonce_timestamp",
		}},
		nil,
	))
	require.Zero(t, mock.ResetSyscallsForProfileCallCount())
	require.Zero(t, mock.StopBpfRecorderCallCount())
}

// TestStoreProfileDisables asserts that disableProfileAfterRecording is
// applied from the recording state.
func TestStoreProfileDisables(t *testing.T) {
	t.Parallel()

	mock := &profilerecorderfakes.FakeImpl{}

	var stored *seccompprofileapi.SeccompProfile

	mock.CreateOrUpdateCalls(func(
		_ context.Context, _ client.Client, obj client.Object, mutate controllerutil.MutateFn,
	) (controllerutil.OperationResult, error) {
		require.NoError(t, mutate())

		var ok bool

		stored, ok = obj.(*seccompprofileapi.SeccompProfile)
		require.True(t, ok)

		return controllerutil.OperationResultCreated, nil
	})

	sut := &RecorderReconciler{impl: mock, log: logr.Discard(), record: events.NewFakeRecorder(10)}
	profile := &seccompprofileapi.SeccompProfile{ObjectMeta: metav1.ObjectMeta{Name: "p"}}

	require.NoError(t, sut.storeProfile(t.Context(), &profileTarget{
		name:  types.NamespacedName{Name: "p"},
		state: recordingState{disable: true},
	}, profile, &profile.Spec.SpecBase, "seccomp"))

	require.Equal(t, profilebase.SpecStateDisabled, stored.Spec.State)
}

func TestCollectBpfProfilesSkipsProfileOfOtherRecording(t *testing.T) {
	t.Parallel()

	recording := &recordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: "recording", Namespace: "recording-ns"},
	}
	scheme := apiruntime.NewScheme()
	require.NoError(t, recordingapi.AddToScheme(scheme))
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(recording).Build()

	mock := &profilerecorderfakes.FakeImpl{}
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()},
		},
	}, nil)
	mock.SyscallsForProfileReturns(&bpfrecorderapi.SyscallsResponse{
		Syscalls: []string{"read"},
		GoArch:   runtime.GOARCH,
	}, nil)
	mock.ClientGetCalls(func(
		_ context.Context, _ client.Client, _ types.NamespacedName, obj client.Object,
	) error {
		recordingResult, ok := obj.(*recordingapi.ProfileRecording)
		require.True(t, ok)
		recording.DeepCopyInto(recordingResult)

		return nil
	})

	mutated := false

	mock.CreateOrUpdateCalls(func(
		_ context.Context,
		_ client.Client,
		obj client.Object,
		mutate controllerutil.MutateFn,
	) (controllerutil.OperationResult, error) {
		// Simulate an existing profile recorded in another namespace.
		obj.SetResourceVersion("1")
		obj.SetLabels(map[string]string{
			recordingapi.ProfileToRecordingLabel:          recording.Name,
			recordingapi.ProfileToRecordingNamespaceLabel: "other-ns",
		})

		err := mutate()
		mutated = err == nil

		return controllerutil.OperationResultNone, err
	})

	sut := &RecorderReconciler{
		impl:   mock,
		client: kubeClient,
		log:    logr.Discard(),
		record: events.NewFakeRecorder(10),
	}
	err := sut.collectBpfProfiles(
		t.Context(),
		"",
		types.NamespacedName{Name: "pod", Namespace: recording.Namespace},
		[]profileToCollect{{
			kind: recordingapi.ProfileRecordingKindSeccompProfile,
			name: "recording_container_nonce_timestamp",
		}},
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, 1, mock.CreateOrUpdateCallCount())
	require.False(t, mutated, "the profile of the other recording must not be updated")
}

// TestStoreProfileConcurrentMerges asserts that nodes merging into the same
// profile at once do not lose each other's updates.
func TestStoreProfileConcurrentMerges(t *testing.T) {
	t.Parallel()

	scheme := apiruntime.NewScheme()
	require.NoError(t, seccompprofileapi.AddToScheme(scheme))
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	mock := &profilerecorderfakes.FakeImpl{}
	mock.CreateOrUpdateCalls(controllerutil.CreateOrUpdate)

	sut := &RecorderReconciler{
		impl:   mock,
		client: kubeClient,
		log:    logr.Discard(),
		record: events.NewFakeRecorder(100),
	}

	labels := map[string]string{
		recordingapi.ProfileToRecordingLabel:          "recording",
		recordingapi.ProfileToRecordingNamespaceLabel: "ns",
		recordingapi.ProfileToContainerLabel:          "ctr",
	}

	const nodes = 8

	var wg sync.WaitGroup

	for node := range nodes {
		wg.Go(func() {
			profile := &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "recording-ctr", Labels: labels},
				Spec: seccompprofileapi.SeccompProfileSpec{
					DefaultAction: seccompprofileapi.ActErrno,
					Syscalls: []seccompprofileapi.Syscall{{
						Action: seccompprofileapi.ActAllow,
						Names:  []string{fmt.Sprintf("syscall_%d", node)},
					}},
				},
			}

			assert.NoError(t, sut.storeProfile(t.Context(), &profileTarget{
				name:          types.NamespacedName{Name: "recording-ctr", Namespace: "ns"},
				recordingName: "recording",
				labels:        labels,
				merge:         true,
			}, profile, &profile.Spec.SpecBase, "seccomp"))
		})
	}

	wg.Wait()

	got := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKey{Name: "recording-ctr"}, got))

	var names []string
	for _, syscall := range got.Spec.Syscalls {
		names = append(names, syscall.Names...)
	}

	require.Len(t, names, nodes)
}

// storeMergedAppArmorProfile stores the recorded AppArmor profile of a
// recording which is gone next to the stored merged profile, and returns the
// AppArmor profiles stored afterwards by name.
func storeMergedAppArmorProfile(
	t *testing.T,
	stored, recorded *apparmorprofileapi.AppArmorAbstract,
	recorder *events.FakeRecorder,
) map[string]apparmorprofileapi.AppArmorProfile {
	t.Helper()

	scheme := apiruntime.NewScheme()
	require.NoError(t, apparmorprofileapi.AddToScheme(scheme))
	require.NoError(t, recordingapi.AddToScheme(scheme))

	labels := map[string]string{
		recordingapi.ProfileToRecordingLabel:          "recording",
		recordingapi.ProfileToRecordingNamespaceLabel: "ns",
		recordingapi.ProfileToContainerLabel:          "ctr",
	}

	merged := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "recording-ctr", Namespace: "ns", Labels: labels},
		Spec:       apparmorprofileapi.AppArmorProfileSpec{Abstract: *stored},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(merged).Build()

	mock := &profilerecorderfakes.FakeImpl{}
	mock.ClientGetCalls(func(
		ctx context.Context, c client.Client, key types.NamespacedName, obj client.Object,
	) error {
		return c.Get(ctx, key, obj)
	})
	mock.CreateOrUpdateCalls(controllerutil.CreateOrUpdate)

	sut := &RecorderReconciler{
		impl:   mock,
		client: kubeClient,
		log:    logr.Discard(),
		record: recorder,
	}

	target, err := sut.resolveProfileTarget(
		t.Context(),
		&parsedAnnotation{profileName: "recording", cntName: "ctr"},
		"",
		types.NamespacedName{Name: "pod", Namespace: "ns"},
		map[string]recordingState{"recording": {partial: true}},
	)
	require.NoError(t, err)
	require.True(t, target.merge)

	profile := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: target.name.Name, Namespace: target.name.Namespace, Labels: target.labels,
		},
		Spec: apparmorprofileapi.AppArmorProfileSpec{Abstract: *recorded},
	}

	require.NoError(
		t,
		sut.storeProfile(t.Context(), target, profile, &profile.Spec.SpecBase, "apparmor"),
	)

	profiles := &apparmorprofileapi.AppArmorProfileList{}
	require.NoError(t, kubeClient.List(t.Context(), profiles))

	byName := map[string]apparmorprofileapi.AppArmorProfile{}
	for i := range profiles.Items {
		byName[profiles.Items[i].Name] = profiles.Items[i]
	}

	return byName
}

// TestStoreProfileMergesAppArmorVariables asserts that recorded AppArmor
// profiles are merged although the recorder writes /proc paths with the pid
// variable, which the merger cannot interpret.
func TestStoreProfileMergesAppArmorVariables(t *testing.T) {
	t.Parallel()

	recorder := events.NewFakeRecorder(10)
	profiles := storeMergedAppArmorProfile(t,
		&apparmorprofileapi.AppArmorAbstract{
			Filesystem: &apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths: []string{"/etc/passwd", "/proc/@{pid}/maps"},
			},
		},
		&apparmorprofileapi.AppArmorAbstract{
			Filesystem: &apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths: []string{"/proc/@{pid}/status"},
			},
		},
		recorder,
	)

	require.Len(t, profiles, 1)
	require.Equal(t,
		[]string{"/etc/passwd", "/proc/@{pid}/maps", "/proc/@{pid}/status"},
		profiles["recording-ctr"].Spec.Abstract.Filesystem.ReadOnlyPaths,
	)
	require.Contains(t, <-recorder.Events, reasonProfileCreated)
}

// TestStoreProfileKeepsProfileWhoseMergeFails asserts that a profile which
// cannot be merged into the final profile is stored as a partial profile
// instead of being retried forever.
func TestStoreProfileKeepsProfileWhoseMergeFails(t *testing.T) {
	t.Parallel()

	stored := &apparmorprofileapi.AppArmorAbstract{
		Filesystem: &apparmorprofileapi.AppArmorFsRules{
			// The merger rejects a path granted by two rules.
			ReadOnlyPaths:  []string{"/etc/passwd"},
			ReadWritePaths: []string{"/etc/passwd"},
		},
	}
	recorded := &apparmorprofileapi.AppArmorAbstract{
		Filesystem: &apparmorprofileapi.AppArmorFsRules{
			ReadOnlyPaths: []string{"/proc/@{pid}/status"},
		},
	}

	recorder := events.NewFakeRecorder(10)
	profiles := storeMergedAppArmorProfile(t, stored, recorded, recorder)

	require.Contains(t, <-recorder.Events, reasonProfileMergeFailed)
	require.Contains(t, <-recorder.Events, reasonProfileCreated)

	require.Len(t, profiles, 2)
	require.Equal(t, *stored, profiles["recording-ctr"].Spec.Abstract)

	partial, ok := profiles["recording-ctr-pod"]
	require.True(t, ok)
	require.Equal(t, *recorded, partial.Spec.Abstract)
	require.Equal(t, "true", partial.Labels[profilebase.ProfilePartialLabel])
	require.Equal(t, "recording", partial.Labels[recordingapi.ProfileToRecordingLabel])
}
