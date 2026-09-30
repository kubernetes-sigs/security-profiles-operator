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

package selinuxprofile

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

type controllerBuilder func(*ctrl.Builder, *ReconcileSelinux) error

type SelinuxObjectHandler interface {
	Init(context.Context, client.Client, types.NamespacedName) error
	GetProfileObject() selinuxprofileapi.SelinuxProfileObject
	Validate(ctx context.Context) error
	GetCILPolicy() (string, error)
}

// SelinuxObjectHandlerInit returns the handler of the object with the given
// key. The operator namespace is the one the SPOD lives in.
type SelinuxObjectHandlerInit func(
	ctx context.Context, cli client.Client, key types.NamespacedName, operatorNamespace string,
) (SelinuxObjectHandler, error)
