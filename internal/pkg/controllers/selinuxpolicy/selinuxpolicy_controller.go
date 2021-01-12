/*
Copyright 2020 The Kubernetes Authors.

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

package selinuxpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"text/template"
	"time"

	rcommonv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	spov1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxpolicy/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/spod/bindata"
)

// The underscore is not a valid character in a pod, so we can
// safely use it as a separator.
const policyWrapper = `(block {{.Name}}_{{.Namespace}}
    {{.Policy}}
)`

const selinuxFinalizerName = "selinuxpolicy.finalizers.selinuxpolicy.k8s.io"

const (
	selinuxdPoliciesBaseURL = "http://unix/policies/"
	selinuxdSocketTimeout   = 5 * time.Second
)

type sePolStatusType string

const (
	installedStatus sePolStatusType = "Installed"
	failedStatus    sePolStatusType = "Failed"
)

type sePolStatus struct {
	Msg    string
	Status sePolStatusType
}

// blank assignment to verify that ReconcileSelinuxPolicy implements `reconcile.Reconciler`.
var _ reconcile.Reconciler = &ReconcileSP{}

// ReconcileSP reconciles a SelinuxPolicy object.
type ReconcileSP struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client         client.Client
	scheme         *runtime.Scheme
	policyTemplate *template.Template
	record         event.Recorder
}

// Reconcile reads that state of the cluster for a SelinuxPolicy object and makes changes based on the state read
// and what is in the `SelinuxPolicy.Spec`.
func (r *ReconcileSP) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling SelinuxPolicy")

	// Fetch the SelinuxPolicy instance
	instance := &spov1alpha1.SelinuxPolicy{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		return reconcile.Result{}, IgnoreNotFound(err)
	}

	// Set up an initial state
	if instance.Status.State == "" {
		policyCopy := instance.DeepCopy()
		policyCopy.Status.State = spov1alpha1.PolicyStatePending
		policyCopy.Status.SetConditions(rcommonv1.Creating())
		if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "Updating SelinuxPolicy status to PENDING")
		}
		return reconcile.Result{}, nil
	}

	// If "apply" is false, no need to do anything, let the deployer
	// review it.
	if !instance.Spec.Apply {
		policyCopy := instance.DeepCopy()
		policyCopy.Status.State = spov1alpha1.PolicyStatePending
		policyCopy.Status.SetConditions(rcommonv1.Unavailable())
		if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "Updating SelinuxPolicy status to PENDING")
		}
		return reconcile.Result{}, nil
	}

	if instance.Status.Usage != GetPolicyUsage(instance.Name, instance.Namespace) {
		if err := r.addUsageStatus(instance); err != nil {
			return reconcile.Result{}, err
		}
	}

	if instance.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted
		if !SliceContainsString(instance.ObjectMeta.Finalizers, selinuxFinalizerName) {
			return r.addFinalizer(instance)
		}
		return r.reconcilePolicy(instance, reqLogger)
	}

	// The object is being deleted

	// Set appropriate condition if needed.
	if !instance.Status.GetCondition(rcommonv1.TypeReady).Equal(rcommonv1.Deleting()) {
		policyCopy := instance.DeepCopy()
		policyCopy.Status.SetConditions(rcommonv1.Deleting())
		if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "Updating SelinuxPolicy status condition to indicate deletion")
		}
		return reconcile.Result{}, nil
	}

	if SliceContainsString(instance.ObjectMeta.Finalizers, selinuxFinalizerName) {
		res, err := r.reconcileDeletePolicy(instance, reqLogger)
		if res.Requeue || err != nil {
			return res, err
		}

		// We only remove the finalizer once the ConfigMap is deleted
		return r.removeFinalizer(instance)
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileSP) addFinalizer(sp *spov1alpha1.SelinuxPolicy) (reconcile.Result, error) {
	spcopy := sp.DeepCopy()
	spcopy.ObjectMeta.Finalizers = append(spcopy.ObjectMeta.Finalizers, selinuxFinalizerName)
	if err := r.client.Update(context.Background(), spcopy); err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Adding finalizer to SelinuxPolicy")
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSP) addUsageStatus(sp *spov1alpha1.SelinuxPolicy) error {
	spcopy := sp.DeepCopy()
	spcopy.Status.Usage = GetPolicyUsage(spcopy.Name, spcopy.Namespace)
	if err := r.client.Status().Update(context.Background(), spcopy); err != nil {
		return errors.Wrap(err, "Updating SelinuxPolicy usage status")
	}
	return nil
}

func (r *ReconcileSP) removeFinalizer(sp *spov1alpha1.SelinuxPolicy) (reconcile.Result, error) {
	spcopy := sp.DeepCopy()
	spcopy.ObjectMeta.Finalizers = RemoveStringFromSlice(spcopy.ObjectMeta.Finalizers, selinuxFinalizerName)
	if err := r.client.Update(context.Background(), spcopy); err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Removing SelinuxPolicy finalizer")
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSP) reconcilePolicy(sp *spov1alpha1.SelinuxPolicy, l logr.Logger) (reconcile.Result, error) {
	err := r.reconcilePolicyFile(sp, l)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Creating policy file")
	}

	l.Info("Checking if policy is installed", "policyName", sp.Name)
	polStatus, err := r.getPolicyStatus(sp)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Looking up policy status")
	}

	if polStatus == nil {
		l.Info("Policy still missing, requeue")
		policyCopy := sp.DeepCopy()
		policyCopy.Status.State = spov1alpha1.PolicyStateInProgress
		policyCopy.Status.SetConditions(rcommonv1.Creating())
		if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "Updating SELinux policy with installation in progress")
		}
		return reconcile.Result{Requeue: true}, nil
	}

	l.Info("Policy installed")
	policyCopy := sp.DeepCopy()

	switch polStatus.Status {
	case installedStatus:
		policyCopy.Status.State = spov1alpha1.PolicyStateInstalled
		policyCopy.Status.SetConditions(rcommonv1.Available())
	case failedStatus:
		policyCopy.Status.State = spov1alpha1.PolicyStateError
		policyCopy.Status.SetConditions(rcommonv1.Unavailable())
	}

	if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Updating SELinux policy with installation success")
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileSP) reconcilePolicyFile(sp *spov1alpha1.SelinuxPolicy, l logr.Logger) error {
	policyPath := path.Join(bindata.SelinuxDropDirectory, GetPolicyName(sp.Name, sp.Namespace)+".cil")
	policyContent := []byte(r.wrapPolicy(sp))

	l.Info("Writing to policy file", "policyPath", policyPath)
	err := ioutil.WriteFile(policyPath, policyContent, 0600)
	if err != nil {
		return errors.Wrap(err, "Writing policy file")
	}

	return nil
}

func (r *ReconcileSP) reconcileDeletePolicy(sp *spov1alpha1.SelinuxPolicy, l logr.Logger) (reconcile.Result, error) {
	res, err := r.reconcileDeletePolicyFile(sp, l)
	if res.Requeue || err != nil {
		return res, err
	}

	l.Info("Checking if policy is removed", "policyName", sp.Name)
	polStatus, err := r.getPolicyStatus(sp)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Looking up policy status")
	}

	if polStatus != nil {
		switch polStatus.Status {
		case installedStatus:
			l.Info("Policy still installed, requeue")
			return reconcile.Result{Requeue: true}, nil
		case failedStatus:
			policyCopy := sp.DeepCopy()
			policyCopy.Status.State = spov1alpha1.PolicyStateError
			policyCopy.Status.SetConditions(rcommonv1.Unavailable())
			if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
				return reconcile.Result{}, errors.Wrap(err, "Updating SELinux policy with installation success")
			}

			return reconcile.Result{}, nil
		}
	}

	l.Info("Policy removed")
	return reconcile.Result{}, nil
}

func (r *ReconcileSP) reconcileDeletePolicyFile(sp *spov1alpha1.SelinuxPolicy,
	l logr.Logger) (reconcile.Result, error) {
	policyPath := path.Join(bindata.SelinuxDropDirectory, GetPolicyName(sp.Name, sp.Namespace)+".cil")

	l.Info("Removing policy file", "policyPath", policyPath)
	err := os.Remove(policyPath)
	if err == nil {
		// Reconcile again to make sure the file is gone
		return reconcile.Result{Requeue: true}, nil
	}

	var osPathErr *os.PathError
	if errors.As(err, &osPathErr) {
		if errors.Is(osPathErr.Err, os.ErrNotExist) {
			// The file is gone, stop requeuing
			return reconcile.Result{}, nil
		}
	}

	// Retry on a generic error
	return reconcile.Result{Requeue: true}, errors.Wrap(err, "error removing policy file")
}

func (r *ReconcileSP) wrapPolicy(cr *spov1alpha1.SelinuxPolicy) string {
	parsedpolicy := strings.TrimSpace(cr.Spec.Policy)
	// ident
	parsedpolicy = strings.ReplaceAll(parsedpolicy, "\n", "\n    ")
	// replace empty lines
	parsedpolicy = strings.TrimSpace(parsedpolicy)
	data := struct {
		Name      string
		Namespace string
		Policy    string
	}{
		Name:      cr.Name,
		Namespace: cr.Namespace,
		Policy:    parsedpolicy,
	}
	var result bytes.Buffer
	if err := r.policyTemplate.Execute(&result, data); err != nil {
		log.Error(err, "Couldn't render policy", "SelinuxPolicy.Name", cr.GetName())
	}
	return result.String()
}

func (r *ReconcileSP) getPolicyStatus(sp *spov1alpha1.SelinuxPolicy) (*sePolStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), selinuxdSocketTimeout)
	defer cancel()

	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", bindata.SelinuxdSocketPath)
			},
		},
	}

	polURL := selinuxdPoliciesBaseURL + GetPolicyName(sp.Name, sp.Namespace)
	req, err := http.NewRequestWithContext(ctx, "GET", polURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a request to selinuxd")
	}

	response, err := httpc.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send a request to selinuxd")
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return nil, nil
	} else if response.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected HTTP error code " + fmt.Sprint(response.StatusCode))
	}

	var status sePolStatus
	err = json.NewDecoder(response.Body).Decode(&status)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode response from selinuxd")
	}

	switch status.Status {
	case installedStatus, failedStatus:
		return &status, nil
	}

	return nil, errors.New("invalid sePolStatus value")
}
