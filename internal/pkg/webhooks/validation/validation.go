/*
Copyright 2026 The Kubernetes Authors.

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

package validation

import (
	"context"
	"net/http"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
)

// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles,verbs=get;list;watch

type rawSelinuxProfileValidator struct {
	decoder admission.Decoder
	log     logr.Logger
}

func RegisterWebhook(server webhook.Server, scheme *runtime.Scheme) {
	server.Register(
		"/validate-rawselinuxprofile",
		&webhook.Admission{
			Handler: &rawSelinuxProfileValidator{
				decoder: admission.NewDecoder(scheme),
				log:     logf.Log.WithName("rawselinuxprofile-validation"),
			},
		},
	)
}

//nolint:gocritic // req passed by value per admission.Handler interface
func (v *rawSelinuxProfileValidator) Handle(
	_ context.Context, req admission.Request,
) admission.Response {
	rsp := &selxv1alpha2.RawSelinuxProfile{}
	if err := v.decoder.Decode(req, rsp); err != nil {
		v.log.Error(err, "failed to decode RawSelinuxProfile")

		return admission.Errored(http.StatusBadRequest, err)
	}

	if err := rsp.ValidatePolicy(); err != nil {
		return admission.Denied(err.Error())
	}

	return admission.Allowed("")
}
