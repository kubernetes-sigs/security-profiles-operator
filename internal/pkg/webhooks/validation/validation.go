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

package validation

import (
	"context"
	"net/http"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

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
	rsp := &selinuxprofileapi.RawSelinuxProfile{}
	if err := v.decoder.Decode(req, rsp); err != nil {
		v.log.Error(err, "failed to decode RawSelinuxProfile")

		return admission.Errored(http.StatusBadRequest, err)
	}

	// Updates which do not change the policy, like status updates or the
	// removal of a finalizer, must not be rejected. Otherwise objects stored
	// before a validation rule got tightened could never be deleted.
	if req.Operation == admissionv1.Update {
		if rsp.GetDeletionTimestamp() != nil {
			return admission.Allowed("object is being deleted")
		}

		old := &selinuxprofileapi.RawSelinuxProfile{}
		if err := v.decoder.DecodeRaw(req.OldObject, old); err != nil {
			v.log.Error(err, "failed to decode old RawSelinuxProfile")

			return admission.Errored(http.StatusBadRequest, err)
		}

		if old.Spec.Policy == rsp.Spec.Policy {
			return admission.Allowed("policy unchanged")
		}
	}

	if err := rsp.ValidatePolicy(); err != nil {
		return admission.Denied(err.Error())
	}

	return admission.Allowed("")
}
