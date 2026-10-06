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
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
)

// The block is named after the policy, so that its process type is the usage
// of the profile, like the one of a SelinuxProfile.
const profileWrapper = `(block {{.Name}}
    {{.Policy}}
)`

// NewRawController returns a new empty controller instance.
func NewRawController() controller.Controller {
	return &ReconcileSelinux{
		controllerName:    "rawselinuxprofile",
		objectHandlerInit: newRawSelinuxProfileHandler,
		ctrlBuilder:       rawSelinuxProfileControllerBuild,
	}
}

func rawSelinuxProfileControllerBuild(b *ctrl.Builder, r *ReconcileSelinux) error {
	return b.Named("rawselinuxprofile").
		For(&selinuxprofileapi.RawSelinuxProfile{}, builder.WithPredicates(
			// The resyncs reinstall a policy which got removed from the
			// node.
			predicate.Or(predicate.GenerationChangedPredicate{}, common.ResyncPredicate),
		)).
		// A SelinuxProfile of the same name has the same policy name, so its
		// creation or removal changes which of them owns the policy.
		Watches(
			&selinuxprofileapi.SelinuxProfile{},
			&handler.EnqueueRequestForObject{},
			builder.WithPredicates(existenceChangedPredicate),
		).
		Complete(r)
}

var _ SelinuxObjectHandler = &rawSelinuxProfileHandler{}

type rawSelinuxProfileHandler struct {
	rsp            *selinuxprofileapi.RawSelinuxProfile
	policyTemplate *template.Template
}

func (sph *rawSelinuxProfileHandler) Init(
	ctx context.Context,
	cli client.Client,
	key types.NamespacedName,
) error {
	if err := cli.Get(ctx, key, sph.rsp); err != nil {
		return fmt.Errorf("getting raw selinux profile: %w", err)
	}

	return nil
}

func (sph *rawSelinuxProfileHandler) GetProfileObject() selinuxprofileapi.SelinuxProfileObject {
	return sph.rsp
}

func (sph *rawSelinuxProfileHandler) Validate(_ context.Context) error {
	return sph.rsp.ValidatePolicy()
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
		Name   string
		Policy string
	}{
		Name:   sph.rsp.GetPolicyName(),
		Policy: parsedpolicy,
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
	_ string,
) (SelinuxObjectHandler, error) {
	// Create template to wrap policies.
	// We ignore the error as the wrapper is static.
	tmpl, tmplerr := template.New("profileWrapper").Parse(profileWrapper)
	if tmplerr != nil {
		return nil, tmplerr
	}

	oh := &rawSelinuxProfileHandler{
		rsp:            &selinuxprofileapi.RawSelinuxProfile{},
		policyTemplate: tmpl,
	}
	err := oh.Init(ctx, cli, key)

	return oh, err
}
