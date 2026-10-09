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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
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
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

var (
	errTest = errors.New("error")
	// errNotRecorded is what the BPF recorder returns for a profile without
	// recorded data.
	errNotRecorded = grpcstatus.Error(grpccodes.NotFound, bpfrecorder.ErrNotFound.Error())
	// errRecorderNotRunning is what the BPF recorder returns after it stopped
	// a recording which looked abandoned.
	errRecorderNotRunning = grpcstatus.Error(
		grpccodes.FailedPrecondition, "bpf recorder not running",
	)
)

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

			mock := newFakeImpl()
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
			err := sut.collectBpfProfiles(t.Context(), sut.newBpfRecorderSession(),
				tc.replicaSuffix,
				types.NamespacedName{Name: tc.podName, Namespace: recording.Namespace},
				testPodUID,
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
		name    string
		prepare func(*testing.T, *fakeImpl)
		assert  func(*testing.T, error)
	}{
		{
			name: "Success",
			prepare: func(t *testing.T, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			name: "NewClient fails",
			prepare: func(t *testing.T, mock *fakeImpl) {
				t.Helper()

				mock.NewClientReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "ClientGet fails",
			prepare: func(t *testing.T, mock *fakeImpl) {
				t.Helper()

				mock.ClientGetReturns(errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "no node addresses",
			prepare: func(t *testing.T, mock *fakeImpl) {
				t.Helper()
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "OperatorNamespace fails",
			prepare: func(t *testing.T, mock *fakeImpl) {
				t.Helper()

				mock.ClientGetCalls(func(
					_ context.Context, _ client.Client, _ types.NamespacedName, obj client.Object,
				) error {
					node, ok := obj.(*corev1.Node)
					assert.True(t, ok)

					node.Status.Addresses = []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "127.0.0.1"},
					}

					return nil
				})
				mock.OperatorNamespaceReturns("", errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "NewControllerManagedBy fails",
			prepare: func(t *testing.T, mock *fakeImpl) {
				t.Helper()

				mock.NewControllerManagedByReturns(errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := newFakeImpl()
			tc.prepare(t, mock)

			sut := &RecorderReconciler{impl: mock}

			err := sut.Setup(t.Context(), nil, nil)
			tc.assert(t, err)
		})
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
		name    string
		prepare func(*testing.T, *RecorderReconciler, *fakeImpl)
		assert  func(*testing.T, *RecorderReconciler, error)
	}{
		{
			name: "Success phase pending no annotations",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
				}, nil)
			},
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			name: "success pod not found",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

				mock.GetPodReturns(nil, kerrors.NewNotFound(schema.GroupResource{}, ""))
			},
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			name: "seccomp BPF success record",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

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
			name: "trace annotation without recording does not record",
			// A trace annotation that no ProfileRecording asks for must not
			// start a recording: the annotation is attacker controlled in any
			// namespace where the recording webhook does not run.
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				require.NoError(t, err)

				_, ok := sut.podsToWatch.Load(testRequest.String())
				assert.False(t, ok, "an unauthorized annotation must not be recorded")
			},
		},
		{
			name: "seccomp BPF success collect",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			name: "failed pod is collected",
			// A failed pod is collected like a succeeded one, it does not run
			// anymore either.
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

				profileName := fmt.Sprintf("profile_replica-123_4bbwm_%d", time.Now().Unix())
				sut.podsToWatch.Store(testRequest.String(), podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{{
						kind: recordingapi.ProfileRecordingKindSeccompProfile,
						name: profileName,
					}},
				})

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodFailed},
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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				require.NoError(t, err)

				_, ok := sut.podsToWatch.Load(testRequest.String())
				assert.False(t, ok, "the failed pod must be collected")
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "seccomp BPF GoArchToSeccompArch fails",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "seccomp BPF CreateOrUpdate fails",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "seccomp BPF DialBpfRecorder fails on collect",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "seccomp BPF DialBpfRecorder fails on StopBpfRecorder",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "seccomp BPF invalid profile name",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "seccomp BPF SyscallsForProfile returns not found",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
				mock.SyscallsForProfileReturns(nil, errNotRecorded)
				mock.StopBpfRecorderReturns(nil)
			},
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "seccomp BPF SyscallsForProfile fails",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "seccomp BPF DialBpfRecorder fails on record",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "seccomp BPF StartBpfRecorder fails",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "seccomp BPF GetSPOD fails",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "seccomp BPF not enabled",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "seccomp BPF nil (defaults to disabled)",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "apparmor BPF success record",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

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
		{
			name: "apparmor BPF success collect",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			name: "apparmor BPF CreateOrUpdate fails",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "apparmor BPF DialBpfRecorder fails on collect",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "apparmor BPF DialBpfRecorder fails on StopBpfRecorder",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "apparmor BPF invalid profile name",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "apparmor BPF ApparmorForProfile returns not found",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
				mock.ApparmorForProfileReturns(nil, errNotRecorded)
				mock.StopBpfRecorderReturns(nil)
			},
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "apparmor BPF ApparmorForProfiles fails",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "apparmor BPF DialBpfRecorder fails on record",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "apparmor BPF StartBpfRecorder fails",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "apparmor BPF GetSPOD fails",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "apparmor BPF not enabled",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "apparmor BPF nil (defaults to disabled)",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "parseBpfAnnotations failed",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: "",
						},
					},
				}, nil)
			},
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			name: "parseLogAnnotations failed",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordLogsAnnotationKey: "",
						},
					},
				}, nil)
			},
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			name: "failure GetPod (error reading pod)",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

				mock.GetPodReturns(nil, errTest)
			},
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "log seccomp success record",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

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
			name: "log selinux success record",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

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
		{
			name: "logs seccomp success collect",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
				mock.SyscallsCalls(func(
					_ context.Context, _ enricherapi.EnricherClient, r *enricherapi.SyscallsRequest,
				) (*enricherapi.SyscallsResponse, error) {
					// Nothing gets recorded after the syscalls got fetched.
					assert.True(t, r.GetCollect())

					return &enricherapi.SyscallsResponse{GoArch: runtime.GOARCH}, nil
				})
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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			name: "logs seccomp failed ResetSyscalls",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "logs seccomp failed CreateOrUpdate",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "logs seccomp failed GoArchToSeccompArch",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "logs seccomp failed Syscalls",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "logs seccomp failed unknown kind",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "logs seccomp wrong profile name",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "logs seccomp DialEnricher fails",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "logs seccomp EnableLogEnricher false",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				// The enricher got disabled while recording, so the pod is
				// given up instead of retried forever.
				require.NoError(t, err)

				_, ok := sut.podsToWatch.Load(testRequest.String())
				assert.False(t, ok)

				recorder, ok := sut.record.(*events.FakeRecorder)
				require.True(t, ok)
				require.Len(t, recorder.Events, 1)
				assert.Contains(t, <-recorder.Events, "Warning "+reasonRecordingAbandoned)
			},
		},
		{
			name: "logs seccomp EnableLogEnricher nil (defaults to disabled)",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				// The enricher got disabled while recording, so the pod is
				// given up instead of retried forever.
				require.NoError(t, err)

				_, ok := sut.podsToWatch.Load(testRequest.String())
				assert.False(t, ok)

				recorder, ok := sut.record.(*events.FakeRecorder)
				require.True(t, ok)
				require.Len(t, recorder.Events, 1)
				assert.Contains(t, <-recorder.Events, "Warning "+reasonRecordingAbandoned)
			},
		},
		{
			name: "logs seccomp failed GetSPOD",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "logs selinux success collect",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
				mock.AvcsCalls(func(
					_ context.Context, _ enricherapi.EnricherClient, r *enricherapi.AvcRequest,
				) (*enricherapi.AvcResponse, error) {
					// Nothing gets recorded after the AVCs got fetched.
					assert.True(t, r.GetCollect())

					return &enricherapi.AvcResponse{
						Avc: []*enricherapi.AvcResponse_SelinuxAvc{
							{
								Tclass:   "class",
								Tcontext: "0:1:2",
							},
						},
					}, nil
				})
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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			name: "logs selinux failed ResetAvcs",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "logs selinux failed CreateOrUpdate",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "logs selinux failed formatSelinuxProfile",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{ //nolint:dupl // test duplicates are fine
			name: "logs selinux failed Avcs",
			prepare: func(t *testing.T, sut *RecorderReconciler, mock *fakeImpl) {
				t.Helper()

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
			assert: func(t *testing.T, sut *RecorderReconciler, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := newFakeImpl()
			sut := &RecorderReconciler{
				impl:   mock,
				log:    logr.Discard(),
				record: events.NewFakeRecorder(10),
			}
			tc.prepare(t, sut, mock)

			_, err := sut.Reconcile(t.Context(), testRequest)
			tc.assert(t, sut, err)
		})
	}
}

func TestIsPodOnLocalNode(t *testing.T) {
	t.Parallel()

	const ip = "127.0.0.1"

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *RecorderReconciler) apiruntime.Object
		assert  func(*testing.T, bool)
	}{
		{
			name: "success",
			prepare: func(t *testing.T, sut *RecorderReconciler) apiruntime.Object {
				t.Helper()

				sut.nodeAddresses = []string{ip}

				return &corev1.Pod{Status: corev1.PodStatus{HostIP: ip}}
			},
			assert: func(t *testing.T, res bool) {
				t.Helper()

				assert.True(t, res)
			},
		},
		{
			name: "no pod",
			prepare: func(t *testing.T, sut *RecorderReconciler) apiruntime.Object {
				t.Helper()

				return &corev1.PodList{}
			},
			assert: func(t *testing.T, res bool) {
				t.Helper()

				assert.False(t, res)
			},
		},
		{
			name: "not found",
			prepare: func(t *testing.T, sut *RecorderReconciler) apiruntime.Object {
				t.Helper()

				return &corev1.Pod{Status: corev1.PodStatus{HostIP: ip}}
			},
			assert: func(t *testing.T, res bool) {
				t.Helper()

				assert.False(t, res)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut := &RecorderReconciler{}
			obj := tc.prepare(t, sut)

			res := sut.isPodOnLocalNode(obj)
			tc.assert(t, res)
		})
	}
}

func TestIsPodWithTraceAnnotation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *RecorderReconciler) apiruntime.Object
		assert  func(*testing.T, bool)
	}{
		{
			name: "success selinux logs",
			prepare: func(t *testing.T, sut *RecorderReconciler) apiruntime.Object {
				t.Helper()

				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						config.SelinuxProfileRecordLogsAnnotationKey: "",
					},
				}}
			},
			assert: func(t *testing.T, res bool) {
				t.Helper()

				assert.True(t, res)
			},
		},
		{
			name: "success seccomp logs",
			prepare: func(t *testing.T, sut *RecorderReconciler) apiruntime.Object {
				t.Helper()

				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						config.SeccompProfileRecordLogsAnnotationKey: "",
					},
				}}
			},
			assert: func(t *testing.T, res bool) {
				t.Helper()

				assert.True(t, res)
			},
		},
		{
			name: "success seccomp bpf",
			prepare: func(t *testing.T, sut *RecorderReconciler) apiruntime.Object {
				t.Helper()

				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						config.SeccompProfileRecordBpfAnnotationKey: "",
					},
				}}
			},
			assert: func(t *testing.T, res bool) {
				t.Helper()

				assert.True(t, res)
			},
		},
		{
			name: "success apparmor bpf",
			prepare: func(t *testing.T, sut *RecorderReconciler) apiruntime.Object {
				t.Helper()

				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						config.ApparmorProfileRecordBpfAnnotationKey: "",
					},
				}}
			},
			assert: func(t *testing.T, res bool) {
				t.Helper()

				assert.True(t, res)
			},
		},
		{
			name: "no pod",
			prepare: func(t *testing.T, sut *RecorderReconciler) apiruntime.Object {
				t.Helper()

				return &corev1.PodList{}
			},
			assert: func(t *testing.T, res bool) {
				t.Helper()

				assert.False(t, res)
			},
		},
		{
			name: "not found",
			prepare: func(t *testing.T, sut *RecorderReconciler) apiruntime.Object {
				t.Helper()

				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				}}
			},
			assert: func(t *testing.T, res bool) {
				t.Helper()

				assert.False(t, res)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut := &RecorderReconciler{}
			obj := tc.prepare(t, sut)

			res := sut.isPodWithTraceAnnotation(obj)
			tc.assert(t, res)
		})
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

// TestAuthorizedProfilesWarnsOncePerPod asserts that an ignored annotation is
// reported once, and not with every update of the pod.
func TestAuthorizedProfilesWarnsOncePerPod(t *testing.T) {
	t.Parallel()

	mock := newFakeImpl()
	mock.ListRecordingsReturns(&recordingapi.ProfileRecordingList{}, nil)

	recorder := events.NewFakeRecorder(10)
	sut := &RecorderReconciler{impl: mock, log: logr.Discard(), record: recorder}

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "1"}}
	profiles := []profileToCollect{{
		kind: recordingapi.ProfileRecordingKindSeccompProfile,
		name: "other-recording_ctr_4bbwm_1700000000",
	}}

	for range 2 {
		authorized, _, err := sut.authorizedProfiles(
			t.Context(), pod, profiles, recordingapi.ProfileRecorderBpf,
		)
		require.NoError(t, err)
		require.Empty(t, authorized)
	}

	require.Len(t, recorder.Events, 1)

	// Another ignored annotation of the same pod is reported.
	<-recorder.Events

	other := append(slices.Clone(profiles), profileToCollect{
		kind: recordingapi.ProfileRecordingKindSeccompProfile,
		name: "third-recording_ctr_4bbwm_1700000000",
	})
	_, _, err := sut.authorizedProfiles(t.Context(), pod, other, recordingapi.ProfileRecorderBpf)
	require.NoError(t, err)
	require.Len(t, recorder.Events, 1)

	// A new pod of the same name is reported again.
	<-recorder.Events

	pod.UID = "2"
	_, _, err = sut.authorizedProfiles(t.Context(), pod, profiles, recordingapi.ProfileRecorderBpf)
	require.NoError(t, err)
	require.Len(t, recorder.Events, 1)
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
		namespace  *corev1.Namespace
	}{
		{
			// The recording webhook does not apply to the namespace, so the
			// pod author set the annotation.
			name:       "namespace without recording label",
			annotation: testAnnotationValue,
			recordings: bpfSeccompRecordingList(),
			namespace:  &corev1.Namespace{},
		},
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

			mock := newFakeImpl()
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

			if tc.namespace != nil {
				mock.GetNamespaceReturns(tc.namespace, nil)
			}

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

// TestAuthorizedProfilesRequiresRecordingNamespace asserts that annotations
// are only accepted in the namespaces the recording webhook applies to. In the
// other ones, the pod author sets them, even with a matching ProfileRecording.
func TestAuthorizedProfilesRequiresRecordingNamespace(t *testing.T) {
	t.Parallel()

	labeled := func(labels map[string]string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns", Labels: labels}}
	}

	teamSelector := &spodapi.SecurityProfilesOperatorDaemon{Spec: spodapi.SPODSpec{
		Webhook: spodapi.SPODWebhookConfig{Options: []spodapi.WebhookOptions{{
			Name: "recording.spo.io",
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"team": "a"},
			},
		}}},
	}}

	for _, tc := range []struct {
		name         string
		spod         *spodapi.SecurityProfilesOperatorDaemon
		namespace    *corev1.Namespace
		namespaceErr error
		authorized   bool
		wantErr      bool
	}{
		{
			name:       "labeled namespace",
			namespace:  labeled(map[string]string{bindata.EnableRecordingLabel: "true"}),
			authorized: true,
		},
		{
			name:      "namespace without label",
			namespace: labeled(map[string]string{"team": "a"}),
		},
		{
			name:       "namespace selected by the webhook options",
			spod:       teamSelector,
			namespace:  labeled(map[string]string{"team": "a"}),
			authorized: true,
		},
		{
			name:      "labeled namespace not selected by the webhook options",
			spod:      teamSelector,
			namespace: labeled(map[string]string{bindata.EnableRecordingLabel: ""}),
		},
		{
			name:         "namespace gone",
			namespaceErr: kerrors.NewNotFound(corev1.Resource("namespaces"), "ns"),
		},
		{
			name:         "namespace not readable",
			namespaceErr: errTest,
			wantErr:      true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := newFakeImpl()
			mock.ListRecordingsReturns(bpfSeccompRecordingList(), nil)
			mock.GetNamespaceReturns(tc.namespace, tc.namespaceErr)

			if tc.spod != nil {
				mock.GetSPODReturns(tc.spod, nil)
			}

			recorder := events.NewFakeRecorder(10)
			sut := &RecorderReconciler{impl: mock, log: logr.Discard(), record: recorder}

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "1"},
			}
			profiles := []profileToCollect{
				{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: testAnnotationValue},
				{
					kind: recordingapi.ProfileRecordingKindSeccompProfile,
					name: "profile_ctr2_4bbwm_1700000000",
				},
			}

			// Reported once per pod, not with every update of it.
			for range 2 {
				authorized, _, err := sut.authorizedProfiles(
					t.Context(), pod, profiles, recordingapi.ProfileRecorderBpf,
				)

				if tc.wantErr {
					require.ErrorIs(t, err, errTest)

					return
				}

				require.NoError(t, err)

				if tc.authorized {
					require.Equal(t, profiles, authorized)
					require.Empty(t, recorder.Events)

					return
				}

				require.Empty(t, authorized)
				require.Zero(t, mock.ListRecordingsCallCount())
				require.Len(t, recorder.Events, 1)
			}
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

	mock := newFakeImpl()
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

	mock := newFakeImpl()
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

			mock := newFakeImpl()
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

	sut := &RecorderReconciler{impl: newFakeImpl(), log: logr.Discard()}

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

		mock := newFakeImpl()
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

		sut.releaseUnrecordablePod(t.Context(), podName, sut.newBpfRecorderSession())

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

		mock := newFakeImpl()
		sut := &RecorderReconciler{impl: mock, log: logr.Discard()}
		sut.podsToWatch.Store(podName.String(), podToWatch{
			recorder: recordingapi.ProfileRecorderLogs,
			profiles: []profileToCollect{
				{kind: recordingapi.ProfileRecordingKindSeccompProfile, name: "seccomp"},
				{kind: recordingapi.ProfileRecordingKindSelinuxProfile, name: "selinux"},
			},
		})

		sut.releaseUnrecordablePod(t.Context(), podName, sut.newBpfRecorderSession())

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

		mock := newFakeImpl()
		sut := &RecorderReconciler{impl: mock, log: logr.Discard()}

		sut.releaseUnrecordablePod(t.Context(), podName, sut.newBpfRecorderSession())

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

	mock := newFakeImpl()
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

	err := sut.collectBpfProfiles(
		t.Context(),
		sut.newBpfRecorderSession(),
		"",
		podName,
		testPodUID,
		profiles,
		nil,
	)
	require.ErrorIs(t, err, errTest)
	require.Zero(t, mock.ResetApparmorForProfileCallCount())
	require.Zero(t, mock.StopBpfRecorderCallCount())

	err = sut.collectBpfProfiles(
		t.Context(),
		sut.newBpfRecorderSession(),
		"",
		podName,
		testPodUID,
		profiles,
		nil,
	)
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

	mock := newFakeImpl()
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

	mock := newFakeImpl()
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

	require.NoError(t, sut.collectBpfProfiles(t.Context(), sut.newBpfRecorderSession(),
		"",
		types.NamespacedName{Name: "pod", Namespace: recording.Namespace},
		testPodUID,
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
		name      string
		rejection error
		attempts  int
	}{
		{
			name:      "invalid",
			rejection: kerrors.NewInvalid(schema.GroupKind{Kind: "SeccompProfile"}, "p", nil),
			attempts:  1,
		},
		{
			name:      "too large",
			rejection: kerrors.NewRequestEntityTooLargeError("too large"),
			attempts:  1,
		},
		{
			name:      "bad request",
			rejection: kerrors.NewBadRequest("bad request"),
			attempts:  1,
		},
		{
			// A permission may not have been granted yet.
			name:      "forbidden",
			rejection: kerrors.NewForbidden(schema.GroupResource{}, "p", errTest),
			attempts:  maxForbiddenAttempts,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recording := &recordingapi.ProfileRecording{
				ObjectMeta: metav1.ObjectMeta{Name: "recording", Namespace: "ns"},
			}

			mock := newFakeImpl()
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
				err := sut.collectBpfProfiles(t.Context(), sut.newBpfRecorderSession(),
					"",
					types.NamespacedName{Name: "pod", Namespace: recording.Namespace},
					testPodUID,
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
		})
	}
}

// TestCollectBpfProfileRetriesTransientErrors asserts that other errors are
// still retried with the recorded data kept.
func TestCollectBpfProfileRetriesTransientErrors(t *testing.T) {
	t.Parallel()

	recording := &recordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: "recording", Namespace: "ns"},
	}

	mock := newFakeImpl()
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

	require.Error(t, sut.collectBpfProfiles(t.Context(), sut.newBpfRecorderSession(),
		"",
		types.NamespacedName{Name: "pod", Namespace: recording.Namespace},
		testPodUID,
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

	mock := newFakeImpl()

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

	mock := newFakeImpl()
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
	err := sut.collectBpfProfiles(t.Context(), sut.newBpfRecorderSession(),
		"",
		types.NamespacedName{Name: "pod", Namespace: recording.Namespace},
		testPodUID,
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

// TestStoreProfileAddsMissingLabels asserts that a profile recorded before
// the namespace label existed gets it on the next update.
func TestStoreProfileAddsMissingLabels(t *testing.T) {
	t.Parallel()

	scheme := apiruntime.NewScheme()
	require.NoError(t, seccompprofileapi.AddToScheme(scheme))

	old := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "recording-ctr",
			Labels: map[string]string{recordingapi.ProfileToRecordingLabel: "recording"},
		},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(old).Build()

	mock := newFakeImpl()
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
	}
	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "recording-ctr", Labels: labels},
		Spec:       seccompprofileapi.SeccompProfileSpec{DefaultAction: seccompprofileapi.ActErrno},
	}

	require.NoError(t, sut.storeProfile(t.Context(), &profileTarget{
		name:          types.NamespacedName{Name: "recording-ctr", Namespace: "ns"},
		recordingName: "recording",
		labels:        labels,
	}, profile, &profile.Spec.SpecBase, "seccomp"))

	got := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKey{Name: "recording-ctr"}, got))
	require.Equal(t, labels, got.GetLabels())
}

// TestStoreProfileConcurrentMerges asserts that nodes merging into the same
// profile at once do not lose each other's updates.
func TestStoreProfileConcurrentMerges(t *testing.T) {
	t.Parallel()

	scheme := apiruntime.NewScheme()
	require.NoError(t, seccompprofileapi.AddToScheme(scheme))
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	mock := newFakeImpl()
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

	mock := newFakeImpl()
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

// bpfCollectPod prepares mock for the collection of a pod recorded by the BPF
// recorder which succeeded, and tracks it in sut.
func bpfCollectPod(
	sut *RecorderReconciler, mock *fakeImpl, podName types.NamespacedName,
	kind recordingapi.ProfileRecordingKind,
) {
	sut.podsToWatch.Store(podName.String(), podToWatch{
		baseName: podName,
		recorder: recordingapi.ProfileRecorderBpf,
		profiles: []profileToCollect{{kind: kind, name: testAnnotationValue}},
	})

	mock.GetPodReturns(&corev1.Pod{
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}, nil)
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: ptrTrue()}},
	}, nil)
}

// TestCollectBpfProfileRecorderNotRunning asserts that a pod whose recording
// the BPF recorder stopped, for example as abandoned, is released instead of
// being requeued for good.
func TestCollectBpfProfileRecorderNotRunning(t *testing.T) {
	t.Parallel()

	podName := types.NamespacedName{Namespace: "ns", Name: "pod"}

	for _, kind := range []recordingapi.ProfileRecordingKind{
		recordingapi.ProfileRecordingKindSeccompProfile,
		recordingapi.ProfileRecordingKindAppArmorProfile,
	} {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			mock := newFakeImpl()
			recorder := events.NewFakeRecorder(10)
			sut := &RecorderReconciler{impl: mock, log: logr.Discard(), record: recorder}
			bpfCollectPod(sut, mock, podName, kind)
			mock.SyscallsForProfileReturns(nil, errRecorderNotRunning)
			mock.ApparmorForProfileReturns(nil, errRecorderNotRunning)

			_, err := sut.Reconcile(t.Context(), reconcile.Request{NamespacedName: podName})
			require.NoError(t, err)

			_, tracked := sut.podsToWatch.Load(podName.String())
			require.False(t, tracked)
			require.Contains(t, <-recorder.Events, reasonRecordingAbandoned)
			require.Zero(t, mock.CreateOrUpdateCallCount())
		})
	}
}

// TestCollectBpfProfileIncompleteRead asserts that recorded data which cannot
// be read completely is retried for a while, and then stored as far as it can
// be read instead of keeping the pod and the recorder session for good.
func TestCollectBpfProfileIncompleteRead(t *testing.T) {
	t.Parallel()

	podName := types.NamespacedName{Namespace: "ns", Name: "pod"}
	request := reconcile.Request{NamespacedName: podName}

	mock := newFakeImpl()
	recorder := events.NewFakeRecorder(10)
	sut := &RecorderReconciler{impl: mock, log: logr.Discard(), record: recorder}
	bpfCollectPod(sut, mock, podName, recordingapi.ProfileRecordingKindSeccompProfile)
	mock.ListRecordingsReturns(bpfSeccompRecordingList(), nil)
	mock.SyscallsForProfileCalls(func(
		_ context.Context, _ bpfrecorderapi.BpfRecorderClient, req *bpfrecorderapi.ProfileRequest,
	) (*bpfrecorderapi.SyscallsResponse, error) {
		if !req.GetAllowPartial() {
			return nil, grpcstatus.Error(grpccodes.DataLoss, "unable to read all recorded syscalls")
		}

		return &bpfrecorderapi.SyscallsResponse{
			Syscalls:   []string{"read"},
			GoArch:     runtime.GOARCH,
			Incomplete: true,
		}, nil
	})

	// The attempts alone are not enough within the grace period.
	sut.incompleteReadGracePeriod = time.Hour

	for range maxIncompleteReadAttempts {
		_, err := sut.Reconcile(t.Context(), request)
		require.ErrorIs(t, err, errIncompleteRead)
	}

	require.Zero(t, mock.CreateOrUpdateCallCount())
	require.Zero(t, mock.ResetSyscallsForProfileCallCount())
	require.Zero(t, mock.StopBpfRecorderCallCount())

	sut.incompleteReadGracePeriod = 0

	_, err := sut.Reconcile(t.Context(), request)
	require.NoError(t, err)

	require.Equal(t, 1, mock.CreateOrUpdateCallCount())
	require.Equal(t, 1, mock.ResetSyscallsForProfileCallCount())
	require.Equal(t, 1, mock.StopBpfRecorderCallCount())

	_, _, partial := mock.SyscallsForProfileArgsForCall(mock.SyscallsForProfileCallCount() - 1)
	require.True(t, partial.GetAllowPartial())

	counted := false

	sut.incompleteReads.Range(func(any, any) bool {
		counted = true

		return false
	})
	require.False(t, counted)

	close(recorder.Events)

	reasons := []string{}
	for event := range recorder.Events {
		reasons = append(reasons, event)
	}

	require.True(t, slices.ContainsFunc(reasons, func(event string) bool {
		return strings.Contains(event, reasonRecordingIncomplete)
	}), reasons)
}

func TestBpfRecorderError(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		err          error
		wantIs       error
		unrecordable bool
	}{
		{name: "not found", err: errNotRecorded, wantIs: errRecordedProfileNotFound},
		{
			name:         "failed precondition",
			err:          errRecorderNotRunning,
			wantIs:       errBpfRecorderUnavailable,
			unrecordable: true,
		},
		{
			// Only the status code tells the errors apart.
			name:   "message of not found without its code",
			err:    grpcstatus.Error(grpccodes.Unknown, bpfrecorder.ErrNotFound.Error()),
			wantIs: nil,
		},
		{
			name:   "data loss",
			err:    grpcstatus.Error(grpccodes.DataLoss, "unable to read all recorded syscalls"),
			wantIs: errIncompleteRead,
		},
		{name: "other error", err: errTest, wantIs: errTest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut := &RecorderReconciler{log: logr.Discard()}

			err := sut.bpfRecorderError(tc.err, "apparmor rules", "profile")
			require.Error(t, err)

			if tc.wantIs != nil {
				require.ErrorIs(t, err, tc.wantIs)
			}

			if !errors.Is(tc.wantIs, errRecordedProfileNotFound) {
				require.NotErrorIs(t, err, errRecordedProfileNotFound)
				require.Contains(t, err.Error(), "getting apparmor rules for profile")
			}

			require.Equal(t, tc.unrecordable, unrecordable(err))
		})
	}
}

// TestRejectedForGoodPerPodAndProfile asserts that the forbidden attempts are
// counted per pod and namespaced profile, and dropped with the pod.
func TestRejectedForGoodPerPodAndProfile(t *testing.T) {
	t.Parallel()

	forbidden := kerrors.NewForbidden(schema.GroupResource{}, "profile", errTest)
	keyOf := func(namespace string) attemptKey {
		return attemptKey{
			pod:     types.NamespacedName{Namespace: namespace, Name: "pod"},
			profile: types.NamespacedName{Namespace: namespace, Name: "profile"},
		}
	}

	sut := &RecorderReconciler{impl: newFakeImpl(), log: logr.Discard()}

	for range maxForbiddenAttempts - 1 {
		require.False(t, sut.rejectedForGood(keyOf("a"), forbidden))
	}

	// The profile of the same name in another namespace has its own count.
	require.False(t, sut.rejectedForGood(keyOf("b"), forbidden))

	// The attempts alone are not enough within the grace period.
	sut.forbiddenGracePeriod = time.Hour
	require.False(t, sut.rejectedForGood(keyOf("a"), forbidden))

	sut.forbiddenGracePeriod = 0
	require.True(t, sut.rejectedForGood(keyOf("a"), forbidden))

	_, counted := sut.forbiddenAttempts.Load(keyOf("a"))
	require.False(t, counted)

	sut.releaseUnrecordablePod(t.Context(), keyOf("b").pod, sut.newBpfRecorderSession())

	_, counted = sut.forbiddenAttempts.Load(keyOf("b"))
	require.False(t, counted)
}

// TestReconcileReplacedPod asserts that a pod which got deleted and created
// again under the same name gets the profiles of the previous one collected
// before it is recorded itself.
func TestReconcileReplacedPod(t *testing.T) {
	t.Parallel()

	podName := types.NamespacedName{Namespace: "ns", Name: "pod"}

	for _, tc := range []struct {
		name       string
		collectErr error
	}{
		{name: "previous pod collected"},
		{name: "collecting the previous pod fails", collectErr: errTest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := newFakeImpl()
			sut := &RecorderReconciler{
				impl: mock, log: logr.Discard(), record: events.NewFakeRecorder(10),
			}
			bpfCollectPod(sut, mock, podName, recordingapi.ProfileRecordingKindSeccompProfile)

			previous, ok := sut.podsToWatch.Load(podName.String())
			require.True(t, ok)

			tracked, ok := previous.(podToWatch)
			require.True(t, ok)

			tracked.uid = "previous"
			sut.podsToWatch.Store(podName.String(), tracked)

			mock.GetPodReturns(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName.Name,
					Namespace: podName.Namespace,
					UID:       "current",
					Annotations: map[string]string{
						config.SeccompProfileRecordBpfAnnotationKey + "ctr": testAnnotationValue,
					},
				},
				Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "ctr"}}},
				Status: corev1.PodStatus{Phase: corev1.PodPending},
			}, nil)
			mock.ListRecordingsReturns(bpfSeccompRecordingList(), nil)
			mock.SyscallsForProfileReturns(&bpfrecorderapi.SyscallsResponse{
				Syscalls: []string{"read"},
				GoArch:   runtime.GOARCH,
			}, tc.collectErr)

			_, err := sut.Reconcile(t.Context(), reconcile.Request{NamespacedName: podName})

			value, ok := sut.podsToWatch.Load(podName.String())
			require.True(t, ok)

			watched, ok := value.(podToWatch)
			require.True(t, ok)

			if tc.collectErr != nil {
				require.ErrorIs(t, err, tc.collectErr)
				require.Equal(t, types.UID("previous"), watched.uid)
				require.Zero(t, mock.StartBpfRecorderCallCount())

				return
			}

			require.NoError(t, err)
			require.Equal(t, 1, mock.ResetSyscallsForProfileCallCount())
			require.Equal(t, 1, mock.StopBpfRecorderCallCount())
			require.Equal(t, 1, mock.StartBpfRecorderCallCount())
			require.Equal(t, types.UID("current"), watched.uid)
		})
	}
}
