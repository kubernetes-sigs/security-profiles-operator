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

package selinuxprofile

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
)

type controllerBuilder func(*ctrl.Builder, reconcile.Reconciler) error

type SelinuxObjectHandler interface {
	Init(context.Context, client.Client, types.NamespacedName) error
	GetProfileObject() selxv1alpha2.SelinuxProfileObject
	Validate() error
	GetCILPolicy() (string, error)
}

type SelinuxObjectHandlerInit func(context.Context, client.Client, types.NamespacedName) (SelinuxObjectHandler, error)
