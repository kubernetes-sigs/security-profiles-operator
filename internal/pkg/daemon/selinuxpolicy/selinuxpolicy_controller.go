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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	selinuxpolicyv1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxpolicy/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// The underscore is not a valid character in a pod, so we can
// safely use it as a separator.
const policyWrapper = `(block {{.Name}}_{{.Namespace}}
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

// Security Profiles Operator RBAC permissions to manage SelinuxPolicy
// nolint:lll
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxpolicies,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxpolicies/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;create;update;patch;delete

// Reconcile reads that state of the cluster for a SelinuxPolicy object and makes changes based on the state read
// and what is in the `SelinuxPolicy.Spec`.
func (r *ReconcileSP) Reconcile(_ context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling SelinuxPolicy")

	// Fetch the SelinuxPolicy instance
	instance := &selinuxpolicyv1alpha1.SelinuxPolicy{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		return reconcile.Result{}, IgnoreNotFound(err)
	}

	nodeStatus, err := nodestatus.NewForProfile(instance)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "cannot create nodeStatus")
	}

	if instance.Status.Usage != GetPolicyUsage(instance.Name, instance.Namespace) {
		if err := r.addUsageStatus(instance); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}

	if instance.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted
		if err := r.ensureNodeStatus(context.TODO(), nodeStatus, instance); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "ensuring node status exists")
		}

		return r.reconcilePolicy(instance, nodeStatus, reqLogger)
	}

	// The object is being deleted
	setTerminatingStatus := func(sp *selinuxpolicyv1alpha1.SelinuxPolicy) *selinuxpolicyv1alpha1.SelinuxPolicyStatus {
		statusCopy := instance.Status.DeepCopy()
		statusCopy.SetConditions(rcommonv1.Deleting())
		statusCopy.State = secprofnodestatusv1alpha1.ProfileStateTerminating
		return statusCopy
	}

	if err := r.setBothStatuses(context.TODO(), nodeStatus, instance, setTerminatingStatus); err != nil {
		reqLogger.Error(err, "cannot update SELinux profile status")
		return reconcile.Result{}, errors.Wrap(err, "updating status for deleted SELinux profile")
	}

	// since the nodeStatus API always removes both the node status and the node's finalizer in sync,
	// this condition will only be true after both are gone and therefore when the profile is really
	// gone from the node
	hasStatus, err := nodeStatus.Exists(context.TODO(), r.client)
	if err != nil || !hasStatus {
		return reconcile.Result{}, errors.Wrap(err, "asserting if node status exists")
	}

	res, err := r.reconcileDeletePolicy(instance, nodeStatus, reqLogger)
	if res.Requeue || err != nil {
		return res, err
	}

	if err := nodeStatus.Remove(context.TODO(), r.client); err != nil {
		reqLogger.Error(err, "cannot remove finalizer from SELinux profile")
		return ctrl.Result{}, errors.Wrap(err, "deleting finalizer for deleted SELinux profile")
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileSP) ensureNodeStatus(
	ctx context.Context, nodeStatus *nodestatus.StatusClient, sp *selinuxpolicyv1alpha1.SelinuxPolicy,
) error {
	if err := nodeStatus.Create(ctx, r.client); err != nil {
		return errors.Wrap(err, "cannot ensure node status")
	}

	// Retry makes sense here as we're updating the shared state directly from multiple nodes
	if err := util.Retry(func() error {
		if sp.Status.State != "" && sp.Spec.Apply {
			return nil
		}

		policyCopy := sp.DeepCopy()
		if sp.Status.State == "" {
			// Set up an initial state
			policyCopy.Status.State = secprofnodestatusv1alpha1.ProfileStatePending
			policyCopy.Status.SetConditions(rcommonv1.Creating())
		} else if !sp.Spec.Apply {
			// If "apply" is false, no need to do anything, let the deployer
			// review it.
			policyCopy.Status.State = secprofnodestatusv1alpha1.ProfileStatePending
			policyCopy.Status.SetConditions(rcommonv1.Unavailable())
		}

		updateErr := r.client.Status().Update(context.TODO(), policyCopy)
		if updateErr != nil {
			if err := r.client.Get(
				ctx, util.NamespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
				return errors.Wrap(err, "retrieving profile")
			}
		}
		return errors.Wrap(updateErr, "updating to initial state")
	}, util.IsNotFoundOrConflict); err != nil {
		return errors.Wrap(err, "Updating SelinuxPolicy status to PENDING")
	}

	return nil
}

// setBothStatuses checks if the node status of a SELinux profile is in sync with the supplied
// SELinux profile and updates the node status if not. Additionally, the status of the
// SELinux profile is set to the lowest common denominator as well.
func (r *ReconcileSP) setBothStatuses(
	ctx context.Context, ns *nodestatus.StatusClient,
	sp *selinuxpolicyv1alpha1.SelinuxPolicy,
	setStatusFn func(sp *selinuxpolicyv1alpha1.SelinuxPolicy) *selinuxpolicyv1alpha1.SelinuxPolicyStatus,
) error {
	if retryErr := util.Retry(func() error {
		if err := r.client.Get(ctx, util.NamespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
			return errors.Wrap(err, "retrieving profile")
		}

		status := setStatusFn(sp)

		policyState, err := ns.SetReturnGlobal(ctx, r.client, status.State)
		if err != nil {
			return errors.Wrap(err, "setting per-node status")
		}

		if sp.Status.State == policyState {
			// avoid needless writes
			return nil
		}

		// this should already be a deep-copy and the only thing we're changing is a scalar..
		sp.Status = *status
		if err := r.client.Status().Update(ctx, sp); err != nil {
			return errors.Wrap(err, "setting SELinux profile status")
		}
		return nil
	}, util.IsNotFoundOrConflict); retryErr != nil {
		return errors.Wrap(retryErr, "updating policy status")
	}

	return nil
}

func (r *ReconcileSP) reconcileInProgressPolicy(
	nodeStatus *nodestatus.StatusClient, sp *selinuxpolicyv1alpha1.SelinuxPolicy,
) error {
	setInProgressStatus := func(sp *selinuxpolicyv1alpha1.SelinuxPolicy) *selinuxpolicyv1alpha1.SelinuxPolicyStatus {
		statusCopy := sp.Status.DeepCopy()
		statusCopy.SetConditions(rcommonv1.Creating())
		statusCopy.State = secprofnodestatusv1alpha1.ProfileStateInProgress
		return statusCopy
	}

	if err := r.setBothStatuses(context.TODO(), nodeStatus, sp, setInProgressStatus); err != nil {
		return errors.Wrap(err, "setting both statuses to in progress")
	}
	return nil
}

func (r *ReconcileSP) addUsageStatus(sp *selinuxpolicyv1alpha1.SelinuxPolicy) error {
	spcopy := sp.DeepCopy()
	spcopy.Status.Usage = GetPolicyUsage(spcopy.Name, spcopy.Namespace)
	if err := r.client.Status().Update(context.Background(), spcopy); err != nil {
		return errors.Wrap(err, "Updating SelinuxPolicy usage status")
	}
	return nil
}

func (r *ReconcileSP) reconcilePolicy(
	sp *selinuxpolicyv1alpha1.SelinuxPolicy, nodeStatus *nodestatus.StatusClient, l logr.Logger,
) (reconcile.Result, error) {
	selinuxdReady, err := isSelinuxdReady()
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "contacting selinuxd")
	}
	if !selinuxdReady {
		l.Info("selinuxd not yet up, requeue")
		return reconcile.Result{Requeue: true}, nil
	}

	err = r.reconcilePolicyFile(sp, l)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Creating policy file")
	}

	l.Info("Checking if policy is installed", "policyName", sp.Name)
	polStatus, err := getPolicyStatus(sp)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Looking up policy status")
	}

	if polStatus == nil {
		if err := r.reconcileInProgressPolicy(nodeStatus, sp); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "updating in progress status")
		}
		return reconcile.Result{Requeue: true}, nil
	}

	l.Info("Policy installed")
	setInstallationStatus := func(sp *selinuxpolicyv1alpha1.SelinuxPolicy) *selinuxpolicyv1alpha1.SelinuxPolicyStatus {
		statusCopy := sp.Status.DeepCopy()

		switch polStatus.Status {
		case installedStatus:
			statusCopy.State = secprofnodestatusv1alpha1.ProfileStateInstalled
			statusCopy.SetConditions(rcommonv1.Available())
		case failedStatus:
			statusCopy.State = secprofnodestatusv1alpha1.ProfileStateError
			statusCopy.SetConditions(rcommonv1.Unavailable())
		}
		return statusCopy
	}

	if err := r.setBothStatuses(context.TODO(), nodeStatus, sp, setInstallationStatus); err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Updating SELinux policy with installation success")
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileSP) reconcilePolicyFile(sp *selinuxpolicyv1alpha1.SelinuxPolicy, l logr.Logger) error {
	policyPath := path.Join(bindata.SelinuxDropDirectory, GetPolicyName(sp.Name, sp.Namespace)+".cil")
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
	sp *selinuxpolicyv1alpha1.SelinuxPolicy, nodeStatus *nodestatus.StatusClient, l logr.Logger,
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
			setFailedStatus := func(sp *selinuxpolicyv1alpha1.SelinuxPolicy) *selinuxpolicyv1alpha1.SelinuxPolicyStatus {
				statusCopy := sp.Status.DeepCopy()
				statusCopy.State = secprofnodestatusv1alpha1.ProfileStateError
				statusCopy.SetConditions(rcommonv1.Unavailable())
				return statusCopy
			}
			if err := r.setBothStatuses(context.TODO(), nodeStatus, sp, setFailedStatus); err != nil {
				return reconcile.Result{}, errors.Wrap(err, "Updating SELinux policy with installation success")
			}

			return reconcile.Result{}, nil
		}
	}

	l.Info("Policy removed")
	return reconcile.Result{}, nil
}

func (r *ReconcileSP) reconcileDeletePolicyFile(sp *selinuxpolicyv1alpha1.SelinuxPolicy,
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

func (r *ReconcileSP) wrapPolicy(cr *selinuxpolicyv1alpha1.SelinuxPolicy) string {
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

func getPolicyStatus(sp *selinuxpolicyv1alpha1.SelinuxPolicy) (*sePolStatus, error) {
	polURL := selinuxdPoliciesBaseURL + GetPolicyName(sp.Name, sp.Namespace)
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
