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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	statusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
)

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

// blank assignment to verify that ReconcileSelinux implements `reconcile.Reconciler`.
var _ reconcile.Reconciler = &ReconcileSelinux{}

// errPolicyNotFound is returned if no policy has been found.
var errPolicyNotFound = errors.New("policy not found")

// ReconcileSelinux reconciles a Selinux profile objects.
type ReconcileSelinux struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client            client.Client
	scheme            *runtime.Scheme
	record            event.Recorder
	metrics           *metrics.Metrics
	log               logr.Logger
	controllerName    string
	objectHandlerInit SelinuxObjectHandlerInit
	ctrlBuilder       controllerBuilder
}

// Setup adds a controller that reconciles selinux profiles.
func (r *ReconcileSelinux) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	r.log = logf.Log.WithName(r.controllerName)
	r.client = mgr.GetClient()
	r.scheme = mgr.GetScheme()
	r.record = event.NewAPIRecorder(mgr.GetEventRecorderFor(r.controllerName))
	r.metrics = met

	return r.ctrlBuilder(ctrl.NewControllerManagedBy(mgr), r)
}

// Name returns the name of the controller.
func (r *ReconcileSelinux) Name() string {
	return r.controllerName + "-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *ReconcileSelinux) SchemeBuilder() *scheme.Builder {
	return selxv1alpha2.SchemeBuilder
}

// Healthz is the liveness probe endpoint of the controller.
func (r *ReconcileSelinux) Healthz(*http.Request) error {
	ready, err := isSelinuxdReady()
	if err != nil {
		return errors.Wrapf(err, "getting health status")
	}
	if !ready {
		return errors.New("not ready")
	}
	return nil
}

// nolint:lll
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;create;update;patch;delete

// Reconcile reads that state of the cluster for a SelinuxProfile object and makes changes based on the state read
// and what is in the `SelinuxProfile.Spec`.
func (r *ReconcileSelinux) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := r.log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling object in " + r.controllerName)

	// Fetch the object instance
	oh, err := r.objectHandlerInit(ctx, r.client, request.NamespacedName)
	if err != nil && !kerrors.IsNotFound(err) {
		return reconcile.Result{}, err
	}

	instance := oh.GetProfileObject()

	nodeStatus, err := nodestatus.NewForProfile(instance, r.client)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "cannot create nodeStatus instance")
	}

	if instance.GetDeletionTimestamp().IsZero() {
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

		return r.reconcilePolicy(instance, oh, nodeStatus, reqLogger)
	}

	if err := nodeStatus.SetNodeStatus(context.TODO(), statusv1alpha1.ProfileStateTerminating); err != nil {
		reqLogger.Error(err, "cannot update SELinux profile status")
		r.metrics.IncSelinuxProfileError(reasonCannotUpdatePolicyStatus)
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
	if err != nil {
		reqLogger.Error(err, "cannot delete policy or requeue")
		r.metrics.IncSelinuxProfileError(reasonCannotRemovePolicy)
		r.record.Event(instance, event.Warning(reasonCannotRemovePolicy, err))
		return res, err
	} else if res.Requeue {
		reqLogger.Info("Re-queueing delete request to make sure the policy is gone")
		return res, err
	}

	if err := nodeStatus.Remove(context.TODO(), r.client); err != nil {
		reqLogger.Error(err, "cannot remove finalizer from SELinux profile")
		r.metrics.IncSelinuxProfileError(reasonCannotUpdatePolicyStatus)
		r.record.Event(instance, event.Warning(reasonCannotUpdatePolicyStatus, err))
		return ctrl.Result{}, errors.Wrap(err, "deleting finalizer for deleted SELinux profile")
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileSelinux) reconcilePolicy(
	sp selxv1alpha2.SelinuxProfileObject,
	oh SelinuxObjectHandler,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	selinuxdReady, err := isSelinuxdReady()
	if err != nil {
		r.metrics.IncSelinuxProfileError(reasonCannotContactSelinuxd)
		r.record.Event(sp, event.Warning(reasonCannotContactSelinuxd, err))
		return reconcile.Result{}, errors.Wrap(err, "contacting selinuxd")
	}
	if !selinuxdReady {
		l.Info("selinuxd not yet up, requeue")
		r.record.Event(sp, event.Normal(reasonCannotContactSelinuxd, "selinuxd not yet up, requeue"))
		return reconcile.Result{Requeue: true}, nil
	}

	if valErr := oh.Validate(); valErr != nil {
		if err := nodeStatus.SetNodeStatus(context.TODO(), statusv1alpha1.ProfileStateError); err != nil {
			r.metrics.IncSelinuxProfileError(reasonCannotUpdatePolicyStatus)
			r.record.Event(sp, event.Warning(reasonCannotUpdatePolicyStatus, err))
			return reconcile.Result{}, errors.Wrap(err, "setting node status to error")
		}
		evstr := fmt.Sprintf("Profile failed validation on %s: %s", os.Getenv(config.NodeNameEnvKey), valErr.Error())
		r.metrics.IncSelinuxProfileError(reasonCannotInstallPolicy)
		r.record.Event(sp, event.Warning(reasonCannotInstallPolicy, errors.New(evstr)))
		return reconcile.Result{}, nil
	}

	err = r.reconcilePolicyFile(sp, oh, l)
	if err != nil {
		r.metrics.IncSelinuxProfileError(reasonCannotWritePolicyFile)
		r.record.Event(sp, event.Warning(reasonCannotWritePolicyFile, err))
		return reconcile.Result{}, errors.Wrap(err, "Creating policy file")
	}

	l.Info("Checking if policy deployed", "policyName", sp.GetName())
	polStatus, err := getPolicyStatus(sp)

	if errors.Is(err, errPolicyNotFound) {
		if err := nodeStatus.SetNodeStatus(context.TODO(), statusv1alpha1.ProfileStateInProgress); err != nil {
			r.metrics.IncSelinuxProfileError(reasonCannotUpdatePolicyStatus)
			r.record.Event(sp, event.Warning(reasonCannotUpdatePolicyStatus, err))
			return reconcile.Result{}, errors.Wrap(err, "setting node status to in progress")
		}
		return reconcile.Result{Requeue: true}, nil
	}

	if err != nil {
		r.metrics.IncSelinuxProfileError(reasonCannotGetPolicyStatus)
		r.record.Event(sp, event.Warning(reasonCannotGetPolicyStatus, err))
		return reconcile.Result{}, errors.Wrap(err, "Looking up policy status")
	}

	var polState statusv1alpha1.ProfileState

	switch polStatus.Status {
	case installedStatus:
		polState = statusv1alpha1.ProfileStateInstalled
		evstr := fmt.Sprintf("Successfully saved profile to disk on %s", os.Getenv(config.NodeNameEnvKey))
		r.metrics.IncSelinuxProfileUpdate()
		r.record.Event(sp, event.Normal(reasonInstalledPolicy, evstr))
	case failedStatus:
		polState = statusv1alpha1.ProfileStateError
		evstr := fmt.Sprintf("Failed to save profile to disk on %s: %s", os.Getenv(config.NodeNameEnvKey), polStatus.Msg)
		r.metrics.IncSelinuxProfileError(reasonCannotInstallPolicy)
		r.record.Event(sp, event.Warning(reasonCannotInstallPolicy, errors.New(evstr)))
	}

	l.Info("Policy deployed", "status", polState)

	if err := nodeStatus.SetNodeStatus(context.TODO(), polState); err != nil {
		r.metrics.IncSelinuxProfileError(reasonCannotUpdatePolicyStatus)
		r.record.Event(sp, event.Warning(reasonCannotUpdatePolicyStatus, err))
		return reconcile.Result{}, errors.Wrap(err, "setting profile status")
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileSelinux) reconcilePolicyFile(
	sp selxv1alpha2.SelinuxProfileObject,
	oh SelinuxObjectHandler,
	l logr.Logger,
) error {
	policyPath := path.Join(bindata.SelinuxDropDirectory, sp.GetPolicyName()+".cil")
	cil, parseErr := oh.GetCILPolicy()
	if parseErr != nil {
		return errors.Wrap(parseErr, "Generating CIL")
	}
	policyContent := []byte(cil)

	l.Info("Writing to policy file", "policyPath", policyPath)
	err := writeFileIfDiffers(policyPath, policyContent)
	if err != nil {
		return errors.Wrap(err, "Writing policy file")
	}

	return nil
}

func (r *ReconcileSelinux) reconcileDeletePolicy(
	sp selxv1alpha2.SelinuxProfileObject, nodeStatus *nodestatus.StatusClient, l logr.Logger,
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

	l.Info("Checking if policy is removed", "policyName", sp.GetName())
	polStatus, err := getPolicyStatus(sp)

	if errors.Is(err, errPolicyNotFound) {
		return reconcile.Result{}, nil
	}

	if err != nil {
		r.metrics.IncSelinuxProfileError(reasonCannotGetPolicyStatus)
		return reconcile.Result{}, errors.Wrap(err, "looking up policy status")
	}

	switch polStatus.Status {
	case installedStatus:
		l.Info("Policy still installed, requeue")
		return reconcile.Result{Requeue: true}, nil
	case failedStatus:
		if err := nodeStatus.SetNodeStatus(context.TODO(), statusv1alpha1.ProfileStateError); err != nil {
			r.metrics.IncSelinuxProfileError(reasonCannotRemovePolicy)
			return reconcile.Result{}, errors.Wrap(err, "Updating SELinux policy with installation")
		}

		evstr := fmt.Sprintf("Failed to save profile to disk on %s: %s", os.Getenv(config.NodeNameEnvKey), polStatus.Msg)
		r.record.Event(sp, event.Warning(reasonCannotInstallPolicy, errors.New(evstr)))
		return reconcile.Result{}, nil
	}

	r.metrics.IncSelinuxProfileDelete()
	l.Info("Policy removed")
	return reconcile.Result{}, nil
}

func (r *ReconcileSelinux) reconcileDeletePolicyFile(sp selxv1alpha2.SelinuxProfileObject,
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

func getPolicyStatus(sp selxv1alpha2.SelinuxProfileObject) (*sePolStatus, error) {
	polURL := selinuxdPoliciesBaseURL + sp.GetPolicyName()
	response, err := selinuxdGetRequest(polURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send a request to selinuxd")
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return nil, errPolicyNotFound
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

// writeFileIfDiffers checks if the content of file at filePath are the same as the byte array
// contents, if not, overwrites the file at filePath.
//
// Reopening the same file may seem wasteful and even look like a TOCTOU issue, but the policy
// drop dir is private to this pod, but mostly just calling a single write is much easier codepath
// than mucking around with seeks and truncates to account for all the corner cases.
func writeFileIfDiffers(filePath string, contents []byte) error {
	const filePermissions = 0o600
	file, err := os.OpenFile(filePath, os.O_RDONLY, filePermissions)
	if os.IsNotExist(err) {
		file.Close()
		return ioutil.WriteFile(filePath, contents, filePermissions)
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

	return ioutil.WriteFile(filePath, contents, filePermissions)
}
