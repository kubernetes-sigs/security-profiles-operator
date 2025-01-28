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
	"bytes"
	"context"
	"fmt"
	"html/template"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
)

// The underscore is not a valid character in a pod, so we can
// safely use it as a separator.
const profileWrapper = `(block {{.Name}}_{{.Namespace}}
    {{.Policy}}
)`

// NewController returns a new empty controller instance.
func NewRawController() controller.Controller {
	return &ReconcileSelinux{
		controllerName:    "rawselinuxprofile",
		objectHandlerInit: newRawSelinuxProfileHandler,
		ctrlBuilder:       rawSelinuxProfileControllerBuild,
	}
}

func rawSelinuxProfileControllerBuild(b *ctrl.Builder, r reconcile.Reconciler) error {
	return b.Named("rawselinuxprofile").
		For(&selxv1alpha2.RawSelinuxProfile{}).
		Complete(r)
}

var _ SelinuxObjectHandler = &rawSelinuxProfileHandler{}

type rawSelinuxProfileHandler struct {
	rsp            *selxv1alpha2.RawSelinuxProfile
	policyTemplate *template.Template
}

func (sph *rawSelinuxProfileHandler) Init(
	ctx context.Context,
	cli client.Client,
	key types.NamespacedName,
) error {
	err := cli.Get(ctx, key, sph.rsp)

	return err
}

func (sph *rawSelinuxProfileHandler) GetProfileObject() selxv1alpha2.SelinuxProfileObject {
	return sph.rsp
}

func (sph *rawSelinuxProfileHandler) Validate() error {
	return nil
}

func (sph *rawSelinuxProfileHandler) GetCILPolicy() (string, error) {
	return sph.wrapPolicy()
}

func (sph *rawSelinuxProfileHandler) wrapPolicy() (string, error) {
	parsedpolicy := strings.TrimSpace(sph.rsp.Spec.Policy)
	// ident
	parsedpolicy = strings.ReplaceAll(parsedpolicy, "\n", "\n    ")
	// replace empty lines
	parsedpolicy = strings.TrimSpace(parsedpolicy)
	data := struct {
		Name      string
		Namespace string
		Policy    string
	}{
		Name:      sph.rsp.GetName(),
		Namespace: sph.rsp.GetNamespace(),
		Policy:    parsedpolicy,
	}

	var result bytes.Buffer

	if err := sph.policyTemplate.Execute(&result, data); err != nil {
		return "", fmt.Errorf("couldn't render policy: %w", err)
	}

	return result.String(), nil
}

func newRawSelinuxProfileHandler(
	ctx context.Context,
	cli client.Client,
	key types.NamespacedName,
) (SelinuxObjectHandler, error) {
	// Create template to wrap policies
	//nolint:error // We ignore the error as the wrapper is static
	tmpl, tmplerr := template.New("profileWrapper").Parse(profileWrapper)
	if tmplerr != nil {
		return nil, tmplerr
	}

	oh := &rawSelinuxProfileHandler{
		rsp:            &selxv1alpha2.RawSelinuxProfile{},
		policyTemplate: tmpl,
	}
	err := oh.Init(ctx, cli, key)

	return oh, err
}
