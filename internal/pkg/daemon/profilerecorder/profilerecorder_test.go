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

package profilerecorder

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bpfrecorderapi "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	recordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/profilerecorder/profilerecorderfakes"
)

var errTest = errors.New("error")

func TestName(t *testing.T) {
	t.Parallel()
	sut := NewController()
	assert.Equal(t, sut.Name(), "recorder-spod")
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
					c client.Client, key types.NamespacedName, obj client.Object,
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
				assert.Nil(t, err)
			},
		},
		{ // NewClient fails
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.NewClientReturns(nil, errTest)
			},
			assert: func(err error) {
				assert.NotNil(t, err)
			},
		},
		{ // ClientGet fails
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.ClientGetReturns(errTest)
			},
			assert: func(err error) {
				assert.NotNil(t, err)
			},
		},
		{ // no node addresses
			prepare: func(mock *profilerecorderfakes.FakeImpl) {},
			assert: func(err error) {
				assert.NotNil(t, err)
			},
		},
		{ // NewControllerManagedBy fails
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.NewControllerManagedByReturns(errTest)
			},
			assert: func(err error) {
				assert.NotNil(t, err)
			},
		},
	} {
		mock := &profilerecorderfakes.FakeImpl{}
		tc.prepare(mock)

		sut := &RecorderReconciler{impl: mock}

		err := sut.Setup(context.Background(), nil, nil)
		tc.assert(err)
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
				assert.Nil(t, err)
			},
		},
		{ // success pod not found
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(nil, kerrors.NewNotFound(schema.GroupResource{}, ""))
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Nil(t, err)
			},
		},
		{ // BPF success record
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: "profile",
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Nil(t, err)
				v, ok := sut.podsToWatch.Load(testRequest.NamespacedName.String())
				assert.True(t, ok)
				pod, ok := v.(podToWatch)
				assert.True(t, ok)
				assert.Equal(t, recordingapi.ProfileRecorderBpf, pod.recorder)
				assert.Len(t, pod.profiles, 1)
				assert.Equal(t, recordingapi.ProfileRecordingKindSeccompProfile, pod.profiles[0].kind)
				assert.Equal(t, "profile", pod.profiles[0].name)
				// already tracking
				_, retryErr := sut.Reconcile(context.Background(), testRequest)
				assert.Nil(t, retryErr)
			},
		},
		{ // BPF success collect
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile-%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.NamespacedName.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, nil)
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
					f controllerutil.MutateFn) (controllerutil.OperationResult, error) {
					err := f()
					assert.Nil(t, err)
					return "", nil
				})
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Nil(t, err)
			},
		},
		{ // nolint: dupl
			// BPF GoArchToSeccompArch fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile-%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.NamespacedName.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, nil)
				mock.SyscallsForProfileReturns(
					&bpfrecorderapi.SyscallsResponse{
						Syscalls: []string{"prctl", "mkdir"},
						GoArch:   runtime.GOARCH,
					}, nil,
				)
				mock.GoArchToSeccompArchReturns("", errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
			},
		},
		{ // nolint: dupl
			// BPF CreateOrUpdate fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile-%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.NamespacedName.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, nil)
				mock.SyscallsForProfileReturns(
					&bpfrecorderapi.SyscallsResponse{
						Syscalls: []string{"prctl", "mkdir"},
						GoArch:   runtime.GOARCH,
					}, nil,
				)
				mock.CreateOrUpdateReturns("", errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
			},
		},
		{ // BPF DialBpfRecorder fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile-%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.NamespacedName.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
			},
		},
		{ // BPF DialBpfRecorder fails on StopBpfRecorder
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile-%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.NamespacedName.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, nil)
				mock.SyscallsForProfileReturns(
					&bpfrecorderapi.SyscallsResponse{
						Syscalls: []string{"prctl", "mkdir"},
						GoArch:   runtime.GOARCH,
					}, nil,
				)
				mock.DialBpfRecorderReturns(nil, func() {}, nil)
				mock.StopBpfRecorderReturns(errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
			},
		},
		{ // BPF invalid profile name
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
				sut.podsToWatch.Store(testRequest.NamespacedName.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, nil)
				mock.SyscallsForProfileReturns(
					&bpfrecorderapi.SyscallsResponse{
						Syscalls: []string{"prctl", "mkdir"},
						GoArch:   runtime.GOARCH,
					}, nil,
				)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
			},
		},
		{ // BPF SyscallsForProfile returns not found
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile-%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.NamespacedName.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, nil)
				mock.SyscallsForProfileReturns(nil, bpfrecorder.ErrNotFound)
				mock.StopBpfRecorderReturns(errTest) // will be ignored
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Nil(t, err)
			},
		},
		{ // BPF SyscallsForProfile fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				profileName := fmt.Sprintf("profile-%d", time.Now().Unix())
				value := podToWatch{
					recorder: recordingapi.ProfileRecorderBpf,
					profiles: []profileToCollect{
						{
							kind: recordingapi.ProfileRecordingKindSeccompProfile,
							name: profileName,
						},
					},
				}
				sut.podsToWatch.Store(testRequest.NamespacedName.String(), value)

				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: profileName,
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, nil)
				mock.SyscallsForProfileReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
			},
		},
		{ // BPF DialBpfRecorder fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: "profile-123",
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
			},
		},
		{ // BPF StartBpfRecorder fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: "profile",
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: true},
				}, nil)
				mock.DialBpfRecorderReturns(nil, func() {}, nil)
				mock.StartBpfRecorderReturns(errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
			},
		},
		{ // BPF GetSPOD fails
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: "profile",
						},
					},
				}, nil)
				mock.GetSPODReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
			},
		},
		{ // BPF not enabled
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey: "profile",
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableBpfRecorder: false},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
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
				assert.Nil(t, err)
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
				assert.Nil(t, err)
			},
		},
		{ // parseHookAnnotations failed
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(&corev1.Pod{
					Status: corev1.PodStatus{Phase: corev1.PodPending},
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							config.SeccompProfileRecordHookAnnotationKey: "",
						},
					},
				}, nil)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.Nil(t, err)
			},
		},
		{ // failure GetPod (error reading pod)
			prepare: func(sut *RecorderReconciler, mock *profilerecorderfakes.FakeImpl) {
				mock.GetPodReturns(nil, errTest)
			},
			assert: func(sut *RecorderReconciler, err error) {
				assert.NotNil(t, err)
			},
		},
	} {
		mock := &profilerecorderfakes.FakeImpl{}
		sut := &RecorderReconciler{
			impl:   mock,
			log:    logr.Discard(),
			record: event.NewNopRecorder(),
		}
		tc.prepare(sut, mock)

		_, err := sut.Reconcile(context.Background(), testRequest)
		tc.assert(sut, err)
	}
}
