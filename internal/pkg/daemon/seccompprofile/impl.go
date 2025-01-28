/*
Copyright 2023 The Kubernetes Authors.

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

package seccompprofile

import (
	"context"

	"github.com/go-logr/logr"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	Pull(context.Context, logr.Logger, string, string, string, *v1.Platform, bool) (*artifact.PullResult, error)
	PullResultType(*artifact.PullResult) artifact.PullResultType
	PullResultSeccompProfile(*artifact.PullResult) *seccompprofileapi.SeccompProfile
	ClientGetProfile(
		context.Context, client.Client, client.ObjectKey, ...client.GetOption,
	) (*seccompprofileapi.SeccompProfile, error)
	IncSeccompProfileError(*metrics.Metrics, string)
	RecordEvent(record.EventRecorder, runtime.Object, string, string, string)
	GetSPOD(context.Context, client.Client) (*spodv1alpha1.SecurityProfilesOperatorDaemon, error)
}

func (*defaultImpl) Pull(
	ctx context.Context,
	l logr.Logger,
	from, username, password string,
	platform *v1.Platform,
	disableSignatureVerification bool,
) (*artifact.PullResult, error) {
	return artifact.New(l).Pull(ctx, from, username, password, platform, disableSignatureVerification)
}

func (*defaultImpl) PullResultType(res *artifact.PullResult) artifact.PullResultType {
	return res.Type()
}

func (*defaultImpl) PullResultSeccompProfile(res *artifact.PullResult) *seccompprofileapi.SeccompProfile {
	return res.SeccompProfile()
}

func (*defaultImpl) ClientGetProfile(
	ctx context.Context, c client.Client, key client.ObjectKey, opts ...client.GetOption,
) (*seccompprofileapi.SeccompProfile, error) {
	profile := &seccompprofileapi.SeccompProfile{}
	err := c.Get(ctx, key, profile, opts...)

	return profile, err
}

func (*defaultImpl) IncSeccompProfileError(m *metrics.Metrics, reason string) {
	m.IncSeccompProfileError(reason)
}

func (*defaultImpl) RecordEvent(
	r record.EventRecorder, object runtime.Object, eventtype, reason, message string,
) {
	r.Event(object, eventtype, reason, message)
}

func (*defaultImpl) GetSPOD(
	ctx context.Context, cli client.Client,
) (*spodv1alpha1.SecurityProfilesOperatorDaemon, error) {
	return common.GetSPOD(ctx, cli)
}
