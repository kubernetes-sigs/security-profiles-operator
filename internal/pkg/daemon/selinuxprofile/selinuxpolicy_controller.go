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

package selinuxprofile

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

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	statusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	selinuxprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
)

// The underscore is not a valid character in a pod, so we can
// safely use it as a separator.
const profileWrapper = `(block {{.Name}}_{{.Namespace}}
    {{.Policy}}
)`

const (
	selinuxdSockAddr        = "http://unix"
	selinuxdPoliciesBaseURL = selinuxdSockAddr + "/policies/"
	selinuxdReadyURL        = selinuxdSockAddr + "/ready"
	selinuxdSocketTimeout   = 5 * time.Second

	selinuxdReadyKey = "ready"
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

const (
	reasonCannotContactSelinuxd    event.Reason = "CannotContactSelinuxd"
	reasonCannotRemovePolicy       event.Reason = "CannotRemoveSelinuxPolicy"
	reasonCannotInstallPolicy      event.Reason = "CannotSaveSelinuxPolicy"
	reasonCannotWritePolicyFile    event.Reason = "CannotWritePolicyFile"
	reasonCannotGetPolicyStatus    event.Reason = "CannotGetPolicyStatus"
	reasonCannotUpdatePolicyStatus event.Reason = "CannotUpdatePolicyStatus"

	reasonInstalledPolicy event.Reason = "SavedSelinuxPolicy"
)

// blank assignment to verify that ReconcileSelinuxProfile implements `reconcile.Reconciler`.
var _ reconcile.Reconciler = &ReconcileSP{}

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &ReconcileSP{}
}

// ReconcileSP reconciles a SelinuxProfile object.
type ReconcileSP struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client         client.Client
	scheme         *runtime.Scheme
	policyTemplate *template.Template
	record         event.Recorder
}

// Name returns the name of the controller.
func (r *ReconcileSP) Name() string {
	return "selinux-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *ReconcileSP) SchemeBuilder() *scheme.Builder {
	return selinuxprofilev1alpha1.SchemeBuilder
}

// Security Profiles Operator RBAC permissions to manage SelinuxProfile
// nolint:lll
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;create;update;patch;delete

// Reconcile reads that state of the cluster for a SelinuxProfile object and makes changes based on the state read
// and what is in the `SelinuxProfile.Spec`.
func (r *ReconcileSP) Reconcile(_ context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling SelinuxProfile")

	// Fetch the SelinuxProfile instance
	instance := &selinuxprofilev1alpha1.SelinuxProfile{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		return reconcile.Result{}, IgnoreNotFound(err)
	}

	nodeStatus, err := nodestatus.NewForProfile(instance, r.client)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "cannot create nodeStatus instance")
	}

	if instance.ObjectMeta.DeletionTimestamp.IsZero() {
		ctx := context.Background()
		// The object is not being deleted
		exists, existErr := nodeStatus.Exists(ctx)

		if existErr != nil {
			return reconcile.Result{}, errors.Wrap(existErr, "checking if node status exists")
		}

		if !exists {
			if err := nodeStatus.Create(ctx); err != nil {
				return reconcile.Result{}, errors.Wrap(err, "cannot ensure node status")
			}
		}

		return r.reconcilePolicy(instance, nodeStatus, reqLogger)
	}

	if err := nodeStatus.SetNodeStatus(context.TODO(), statusv1alpha1.ProfileStateTerminating); err != nil {
		reqLogger.Error(err, "cannot update SELinux profile status")
		r.record.Event(instance, event.Warning(reasonCannotUpdatePolicyStatus, err))
		return reconcile.Result{}, errors.Wrap(err, "updating status for deleted SELinux profile")
	}

	// since the nodeStatus API always removes both the node status and the node's finalizer in sync,
	// this condition will only be true after both are gone and therefore when the profile is really
	// gone from the node
	hasStatus, err := nodeStatus.Exists(context.TODO())
	if err != nil || !hasStatus {
		return reconcile.Result{}, errors.Wrap(err, "asserting if node status exists")
	}

	res, err := r.reconcileDeletePolicy(instance, nodeStatus, reqLogger)
	if res.Requeue || err != nil {
		r.record.Event(instance, event.Warning(reasonCannotRemovePolicy, err))
		return res, err
	}

	if err := nodeStatus.Remove(context.TODO(), r.client); err != nil {
		reqLogger.Error(err, "cannot remove finalizer from SELinux profile")
		r.record.Event(instance, event.Warning(reasonCannotUpdatePolicyStatus, err))
		return ctrl.Result{}, errors.Wrap(err, "deleting finalizer for deleted SELinux profile")
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileSP) reconcilePolicy(
	sp *selinuxprofilev1alpha1.SelinuxProfile, nodeStatus *nodestatus.StatusClient, l logr.Logger,
) (reconcile.Result, error) {
	selinuxdReady, err := isSelinuxdReady()
	if err != nil {
		r.record.Event(sp, event.Warning(reasonCannotContactSelinuxd, err))
		return reconcile.Result{}, errors.Wrap(err, "contacting selinuxd")
	}
	if !selinuxdReady {
		l.Info("selinuxd not yet up, requeue")
		r.record.Event(sp, event.Normal(reasonCannotContactSelinuxd, "selinuxd not yet up, requeue"))
		return reconcile.Result{Requeue: true}, nil
	}

	err = r.reconcilePolicyFile(sp, l)
	if err != nil {
		r.record.Event(sp, event.Warning(reasonCannotWritePolicyFile, err))
		return reconcile.Result{}, errors.Wrap(err, "Creating policy file")
	}

	l.Info("Checking if policy deployed", "policyName", sp.Name)
	polStatus, err := getPolicyStatus(sp)
	if err != nil {
		r.record.Event(sp, event.Warning(reasonCannotGetPolicyStatus, err))
		return reconcile.Result{}, errors.Wrap(err, "Looking up policy status")
	}

	if polStatus == nil {
		if err := nodeStatus.SetNodeStatus(context.TODO(), statusv1alpha1.ProfileStateInProgress); err != nil {
			r.record.Event(sp, event.Warning(reasonCannotUpdatePolicyStatus, err))
			return reconcile.Result{}, errors.Wrap(err, "setting node status to in progress")
		}
		return reconcile.Result{Requeue: true}, nil
	}

	var polState statusv1alpha1.ProfileState

	switch polStatus.Status {
	case installedStatus:
		polState = statusv1alpha1.ProfileStateInstalled
		evstr := fmt.Sprintf("Successfully saved profile to disk on %s", os.Getenv(config.NodeNameEnvKey))
		r.record.Event(sp, event.Normal(reasonInstalledPolicy, evstr))
	case failedStatus:
		polState = statusv1alpha1.ProfileStateError
		evstr := fmt.Sprintf("Successfully saved profile to disk on %s", os.Getenv(config.NodeNameEnvKey))
		r.record.Event(sp, event.Warning(reasonCannotInstallPolicy, errors.New(evstr)))
	}

	l.Info("Policy deployed", "status", polState)

	if err := nodeStatus.SetNodeStatus(context.TODO(), polState); err != nil {
		r.record.Event(sp, event.Warning(reasonCannotUpdatePolicyStatus, err))
		return reconcile.Result{}, errors.Wrap(err, "setting profile status")
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileSP) reconcilePolicyFile(sp *selinuxprofilev1alpha1.SelinuxProfile, l logr.Logger) error {
	policyPath := path.Join(bindata.SelinuxDropDirectory, sp.GetPolicyName()+".cil")
	policyContent := []byte(r.wrapPolicy(sp))

	l.Info("Writing to policy file", "policyPath", policyPath)
	err := writeFileIfDiffers(policyPath, policyContent)
	if err != nil {
		return errors.Wrap(err, "Writing policy file")
	}

	return nil
}

// writeFileIfDiffers checks if the content of file at filePath are the same as the byte array
// contents, if not, overwrites the file at filePath.
//
// Reopening the same file may seem wasteful and even look like a TOCTOU issue, but the policy
// drop dir is private to this pod, but mostly just calling a single write is much easier codepath
// than mucking around with seeks and truncates to account for all the corner cases.
func writeFileIfDiffers(filePath string, contents []byte) error {
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
	if os.IsNotExist(err) {
		file.Close()
		return ioutil.WriteFile(filePath, contents, 0600)
	} else if err != nil {
		return errors.Wrap(err, "could not open for reading"+filePath)
	}
	defer file.Close()

	existing, err := ioutil.ReadAll(file)
	if err != nil {
		return errors.Wrap(err, "reading file "+filePath)
	}

	if bytes.Equal(existing, contents) {
		return nil
	}

	return ioutil.WriteFile(filePath, contents, 0600)
}

func (r *ReconcileSP) reconcileDeletePolicy(
	sp *selinuxprofilev1alpha1.SelinuxProfile, nodeStatus *nodestatus.StatusClient, l logr.Logger,
) (reconcile.Result, error) {
	selinuxdReady, err := isSelinuxdReady()
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "contacting selinuxd")
	}
	if !selinuxdReady {
		l.Info("selinuxd not yet up, requeue")
		return reconcile.Result{Requeue: true}, nil
	}

	res, err := r.reconcileDeletePolicyFile(sp, l)
	if res.Requeue || err != nil {
		return res, err
	}

	l.Info("Checking if policy is removed", "policyName", sp.Name)
	polStatus, err := getPolicyStatus(sp)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Looking up policy status")
	}

	if polStatus != nil {
		switch polStatus.Status {
		case installedStatus:
			l.Info("Policy still installed, requeue")
			return reconcile.Result{Requeue: true}, nil
		case failedStatus:
			if err := nodeStatus.SetNodeStatus(context.TODO(), statusv1alpha1.ProfileStateError); err != nil {
				return reconcile.Result{}, errors.Wrap(err, "Updating SELinux policy with installation success")
			}

			return reconcile.Result{}, nil
		}
	}

	l.Info("Policy removed")
	return reconcile.Result{}, nil
}

func (r *ReconcileSP) reconcileDeletePolicyFile(sp *selinuxprofilev1alpha1.SelinuxProfile,
	l logr.Logger) (reconcile.Result, error) {
	policyPath := path.Join(bindata.SelinuxDropDirectory, sp.GetPolicyName()+".cil")

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

func (r *ReconcileSP) wrapPolicy(cr *selinuxprofilev1alpha1.SelinuxProfile) string {
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
		log.Error(err, "Couldn't render policy", "SelinuxProfile.Name", cr.GetName())
	}
	return result.String()
}

func selinuxdGetRequest(url string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), selinuxdSocketTimeout)
	defer cancel()

	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", bindata.SelinuxdSocketPath)
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a request to selinuxd")
	}

	return httpc.Do(req)
}

func isSelinuxdReady() (bool, error) {
	response, err := selinuxdGetRequest(selinuxdReadyURL)
	if err != nil {
		return false, errors.Wrap(err, "failed to send a request to selinuxd")
	}
	defer response.Body.Close()

	var status map[string]bool
	err = json.NewDecoder(response.Body).Decode(&status)
	if err != nil {
		return false, errors.Wrap(err, "failed to decode response from selinuxd")
	}

	return status[selinuxdReadyKey], nil
}

func getPolicyStatus(sp *selinuxprofilev1alpha1.SelinuxProfile) (*sePolStatus, error) {
	polURL := selinuxdPoliciesBaseURL + sp.GetPolicyName()
	response, err := selinuxdGetRequest(polURL)
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
