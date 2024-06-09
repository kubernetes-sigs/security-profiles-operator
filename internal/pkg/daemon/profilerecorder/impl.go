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

	"github.com/containers/common/pkg/seccomp"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bpfrecorderapi "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	enricherapi "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	profilerecording1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	NewClient(ctrl.Manager) (client.Client, error)
	ClientGet(context.Context, client.Client, client.ObjectKey, client.Object) error
	NewControllerManagedBy(
		manager.Manager, string, func(obj runtime.Object) bool,
		func(obj runtime.Object) bool, reconcile.Reconciler) error
	ManagerGetClient(manager.Manager) client.Client
	ManagerGetEventRecorderFor(manager.Manager, string) record.EventRecorder
	GetPod(context.Context, client.Client, client.ObjectKey) (*corev1.Pod, error)
	GetSPOD(context.Context, client.Client) (*spodapi.SecurityProfilesOperatorDaemon, error)
	DialBpfRecorder() (*grpc.ClientConn, context.CancelFunc, error)
	StartBpfRecorder(context.Context, bpfrecorderapi.BpfRecorderClient) error
	StopBpfRecorder(context.Context, bpfrecorderapi.BpfRecorderClient) error
	SyscallsForProfile(
		context.Context,
		bpfrecorderapi.BpfRecorderClient,
		*bpfrecorderapi.ProfileRequest,
	) (*bpfrecorderapi.SyscallsResponse, error)
	CreateOrUpdate(
		context.Context, client.Client, client.Object, controllerutil.MutateFn,
	) (controllerutil.OperationResult, error)
	GoArchToSeccompArch(string) (seccomp.Arch, error)
	Syscalls(
		context.Context, enricherapi.EnricherClient, *enricherapi.SyscallsRequest,
	) (*enricherapi.SyscallsResponse, error)
	ResetSyscalls(
		context.Context, enricherapi.EnricherClient, *enricherapi.SyscallsRequest,
	) error
	Avcs(
		context.Context, enricherapi.EnricherClient, *enricherapi.AvcRequest,
	) (*enricherapi.AvcResponse, error)
	ResetAvcs(
		context.Context, enricherapi.EnricherClient, *enricherapi.AvcRequest,
	) error
	DialEnricher() (*grpc.ClientConn, context.CancelFunc, error)
	GetRecording(context.Context, client.Client, client.ObjectKey) (*profilerecording1alpha1.ProfileRecording, error)
	ApparmorForProfile(
		context.Context,
		bpfrecorderapi.BpfRecorderClient,
		*bpfrecorderapi.ProfileRequest,
	) (*bpfrecorderapi.ApparmorResponse, error)
}

func (*defaultImpl) NewClient(mgr ctrl.Manager) (client.Client, error) {
	return client.New(mgr.GetConfig(), client.Options{})
}

func (*defaultImpl) ClientGet(
	ctx context.Context, c client.Client, key client.ObjectKey, obj client.Object,
) error {
	return c.Get(ctx, key, obj)
}

func (*defaultImpl) NewControllerManagedBy(
	m manager.Manager,
	name string,
	p1 func(obj runtime.Object) bool,
	p2 func(obj runtime.Object) bool,
	r reconcile.Reconciler,
) error {
	return ctrl.NewControllerManagedBy(m).
		Named(name).
		WithEventFilter(predicate.Funcs{
			CreateFunc:  func(e event.CreateEvent) bool { return p1(e.Object) && p2(e.Object) },
			DeleteFunc:  func(e event.DeleteEvent) bool { return p1(e.Object) && p2(e.Object) },
			UpdateFunc:  func(e event.UpdateEvent) bool { return p1(e.ObjectNew) && p2(e.ObjectNew) },
			GenericFunc: func(e event.GenericEvent) bool { return p1(e.Object) && p2(e.Object) },
		}).
		For(&corev1.Pod{}).
		Complete(r)
}

func (*defaultImpl) ManagerGetClient(m manager.Manager) client.Client {
	return m.GetClient()
}

func (*defaultImpl) ManagerGetEventRecorderFor(
	m manager.Manager, name string,
) record.EventRecorder {
	return m.GetEventRecorderFor(name)
}

func (*defaultImpl) GetPod(
	ctx context.Context, c client.Client, key client.ObjectKey,
) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	err := c.Get(ctx, key, pod)
	return pod, err
}

func (*defaultImpl) GetSPOD(
	ctx context.Context, c client.Client,
) (*spodapi.SecurityProfilesOperatorDaemon, error) {
	return common.GetSPOD(ctx, c)
}

func (*defaultImpl) DialBpfRecorder() (*grpc.ClientConn, context.CancelFunc, error) {
	return bpfrecorder.Dial()
}

func (*defaultImpl) StartBpfRecorder(
	ctx context.Context, c bpfrecorderapi.BpfRecorderClient,
) error {
	_, err := c.Start(ctx, &bpfrecorderapi.EmptyRequest{})
	return err
}

func (*defaultImpl) StopBpfRecorder(
	ctx context.Context, c bpfrecorderapi.BpfRecorderClient,
) error {
	_, err := c.Stop(ctx, &bpfrecorderapi.EmptyRequest{})
	return err
}

func (*defaultImpl) SyscallsForProfile(
	ctx context.Context,
	c bpfrecorderapi.BpfRecorderClient,
	req *bpfrecorderapi.ProfileRequest,
) (*bpfrecorderapi.SyscallsResponse, error) {
	return c.SyscallsForProfile(ctx, req)
}

func (*defaultImpl) ApparmorForProfile(
	ctx context.Context,
	c bpfrecorderapi.BpfRecorderClient,
	req *bpfrecorderapi.ProfileRequest,
) (*bpfrecorderapi.ApparmorResponse, error) {
	return c.ApparmorForProfile(ctx, req)
}

func (*defaultImpl) CreateOrUpdate(
	ctx context.Context,
	c client.Client,
	obj client.Object,
	f controllerutil.MutateFn,
) (controllerutil.OperationResult, error) {
	return controllerutil.CreateOrUpdate(ctx, c, obj, f)
}

func (*defaultImpl) GoArchToSeccompArch(goArch string) (seccomp.Arch, error) {
	return seccomp.GoArchToSeccompArch(goArch)
}

func (*defaultImpl) Syscalls(
	ctx context.Context, c enricherapi.EnricherClient, in *enricherapi.SyscallsRequest,
) (*enricherapi.SyscallsResponse, error) {
	return c.Syscalls(ctx, in)
}

func (*defaultImpl) ResetSyscalls(
	ctx context.Context, c enricherapi.EnricherClient, in *enricherapi.SyscallsRequest,
) error {
	_, err := c.ResetSyscalls(ctx, in)
	return err
}

func (*defaultImpl) Avcs(
	ctx context.Context, c enricherapi.EnricherClient, in *enricherapi.AvcRequest,
) (*enricherapi.AvcResponse, error) {
	return c.Avcs(ctx, in)
}

func (*defaultImpl) ResetAvcs(
	ctx context.Context, c enricherapi.EnricherClient, in *enricherapi.AvcRequest,
) error {
	_, err := c.ResetAvcs(ctx, in)
	return err
}

func (*defaultImpl) DialEnricher() (*grpc.ClientConn, context.CancelFunc, error) {
	return enricher.Dial()
}

func (*defaultImpl) GetRecording(
	ctx context.Context,
	cli client.Client,
	key client.ObjectKey,
) (*profilerecording1alpha1.ProfileRecording, error) {
	recording := profilerecording1alpha1.ProfileRecording{}

	err := cli.Get(ctx, key, &recording)
	return &recording, err
}
