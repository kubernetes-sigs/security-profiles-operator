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
	"io/ioutil"

	"github.com/containers/common/pkg/seccomp"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bpfrecorderapi "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	enricherapi "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
type impl interface {
	NewClient(ctrl.Manager) (client.Client, error)
	ClientGet(client.Client, client.ObjectKey, client.Object) error
	NewControllerManagedBy(
		manager.Manager, string, func(obj runtime.Object) bool,
		func(obj runtime.Object) bool, reconcile.Reconciler) error
	ManagerGetClient(manager.Manager) client.Client
	ManagerGetEventRecorderFor(manager.Manager, string) record.EventRecorder
	GetPod(context.Context, client.Client, client.ObjectKey) (*corev1.Pod, error)
	GetSPOD(context.Context, client.Client) (*spodapi.SecurityProfilesOperatorDaemon, error)
	DialBpfRecorder() (*grpc.ClientConn, context.CancelFunc, error)
	StartBpfRecorder(bpfrecorderapi.BpfRecorderClient, context.Context) error
	StopBpfRecorder(bpfrecorderapi.BpfRecorderClient, context.Context) error
	SyscallsForProfile(
		bpfrecorderapi.BpfRecorderClient,
		context.Context,
		*bpfrecorderapi.ProfileRequest,
	) (*bpfrecorderapi.SyscallsResponse, error)
	CreateOrUpdate(
		context.Context, client.Client, client.Object, controllerutil.MutateFn,
	) (controllerutil.OperationResult, error)
	GoArchToSeccompArch(string) (seccomp.Arch, error)
	ReadFile(string) ([]byte, error)
	Syscalls(
		enricherapi.EnricherClient, context.Context, *enricherapi.SyscallsRequest,
	) (*enricherapi.SyscallsResponse, error)
	ResetSyscalls(
		enricherapi.EnricherClient, context.Context, *enricherapi.SyscallsRequest,
	) error
	Avcs(
		enricherapi.EnricherClient, context.Context, *enricherapi.AvcRequest,
	) (*enricherapi.AvcResponse, error)
	ResetAvcs(
		enricherapi.EnricherClient, context.Context, *enricherapi.AvcRequest,
	) error
	DialEnricher() (*grpc.ClientConn, context.CancelFunc, error)
}

func (*defaultImpl) NewClient(mgr ctrl.Manager) (client.Client, error) {
	return client.New(mgr.GetConfig(), client.Options{})
}

func (*defaultImpl) ClientGet(
	c client.Client, key client.ObjectKey, obj client.Object,
) error {
	return c.Get(context.Background(), key, obj)
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
		WithEventFilter(predicate.And(
			resource.NewPredicates(p1),
			resource.NewPredicates(p2),
		)).
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
	c bpfrecorderapi.BpfRecorderClient, ctx context.Context,
) error {
	_, err := c.Start(ctx, &bpfrecorderapi.EmptyRequest{})
	return err
}

func (*defaultImpl) StopBpfRecorder(
	c bpfrecorderapi.BpfRecorderClient, ctx context.Context,
) error {
	_, err := c.Stop(ctx, &bpfrecorderapi.EmptyRequest{})
	return err
}

func (*defaultImpl) SyscallsForProfile(
	c bpfrecorderapi.BpfRecorderClient,
	ctx context.Context,
	req *bpfrecorderapi.ProfileRequest,
) (*bpfrecorderapi.SyscallsResponse, error) {
	return c.SyscallsForProfile(ctx, req)
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

func (*defaultImpl) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func (*defaultImpl) Syscalls(
	c enricherapi.EnricherClient, ctx context.Context, in *enricherapi.SyscallsRequest,
) (*enricherapi.SyscallsResponse, error) {
	return c.Syscalls(ctx, in)
}

func (*defaultImpl) ResetSyscalls(
	c enricherapi.EnricherClient, ctx context.Context, in *enricherapi.SyscallsRequest,
) error {
	_, err := c.ResetSyscalls(ctx, in)
	return err
}

func (*defaultImpl) Avcs(
	c enricherapi.EnricherClient, ctx context.Context, in *enricherapi.AvcRequest,
) (*enricherapi.AvcResponse, error) {
	return c.Avcs(ctx, in)
}

func (*defaultImpl) ResetAvcs(
	c enricherapi.EnricherClient, ctx context.Context, in *enricherapi.AvcRequest,
) error {
	_, err := c.ResetAvcs(ctx, in)
	return err
}

func (*defaultImpl) DialEnricher() (*grpc.ClientConn, context.CancelFunc, error) {
	return enricher.Dial()
}
