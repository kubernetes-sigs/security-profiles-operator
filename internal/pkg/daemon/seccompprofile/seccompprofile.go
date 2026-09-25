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

package seccompprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.podman.io/common/pkg/seccomp"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 5 * time.Minute

	filePermissionMode os.FileMode = 0o644

	// MkdirAll won't create a directory if it does not have the execute bit.
	// https://github.com/golang/go/issues/22323#issuecomment-340568811
	dirPermissionMode os.FileMode = 0o744

	reasonSeccompNotSupported   string = "SeccompNotSupportedOnNode"
	reasonInvalidSeccompProfile string = "InvalidSeccompProfile"
	reasonCannotPullProfile     string = "CannotPullSeccompProfile"
	reasonCannotSaveProfile     string = "CannotSaveSeccompProfile"
	reasonCannotRemoveProfile   string = "CannotRemoveSeccompProfile"
	reasonCannotUpdateProfile   string = "CannotUpdateSeccompProfile"
	reasonProfileNotAllowed     string = "ProfileNotAllowed"
	reasonSavedProfile          string = "SavedSeccompProfile"
	reasonProfileFileConflict   string = "SeccompProfileFileConflict"

	defaultCacheTimeout time.Duration = 24 * time.Hour
	maxCacheItems       uint64        = 1000

	allowedAllRegexp string = ".*"
)

var (
	errSeccompNotSupported = errors.New("seccomp not supported")
	errSeccompProfileNil   = errors.New("seccomp profile cannot be nil")
	errSavingProfile       = errors.New("cannot save profile")
	errCreatingOperatorDir = errors.New("cannot create operator directory")
	errForbiddenSyscall    = errors.New("syscall not allowed")
	errForbiddenProfile    = errors.New("seccomp profile not allowed")
	errForbiddenAction     = errors.New("seccomp action not allowed")
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &Reconciler{
		impl: &defaultImpl{},
		baseProfiles: ttlcache.New(
			ttlcache.WithTTL[string, *seccompprofileapi.SeccompProfile](defaultCacheTimeout),
			ttlcache.WithCapacity[string, *seccompprofileapi.SeccompProfile](maxCacheItems),
			// A base profile referenced by tag has to be pulled again after
			// the TTL to pick up a new version, no matter how often it is
			// used in between. Touching on hit would keep a busy profile
			// stale forever.
			ttlcache.WithDisableTouchOnHit[string, *seccompprofileapi.SeccompProfile](),
		),
	}
}

type saver func(string, []byte) (bool, error)

// A Reconciler reconciles seccomp profiles.
type Reconciler struct {
	impl
	client       client.Client
	log          logr.Logger
	record       util.EventRecorder
	save         saver
	metrics      *metrics.Metrics
	baseProfiles *ttlcache.Cache[string, *seccompprofileapi.SeccompProfile]
	nodeName     string
	// reader reads directly from the API server. It confirms which of two
	// profiles owns a shared file before the file gets written, which must
	// not depend on the cache.
	reader client.Reader
	// profileRoot overrides the directory of the profile files for testing.
	profileRoot string
}

// profilePath returns the path of the file of the profile on the node.
func (r *Reconciler) profilePath(sp *seccompprofileapi.SeccompProfile) string {
	if r.profileRoot != "" {
		return filepath.Join(r.profileRoot, sp.GetProfileFile())
	}

	return sp.GetProfilePath()
}

// apiReader returns the reader for uncached lookups.
func (r *Reconciler) apiReader() client.Reader {
	if r.reader != nil {
		return r.reader
	}

	return r.client
}

// reportError increments the error metric for reason and records a warning
// event on obj.
func (r *Reconciler) reportError(obj apiruntime.Object, reason, action string, err error) {
	common.ErrorReporter{
		Record:   r.record,
		IncError: r.metrics.IncSeccompProfileError,
	}.Report(obj, reason, action, err.Error())
}

// Name returns the name of the controller.
func (r *Reconciler) Name() string {
	return "seccomp-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *Reconciler) SchemeBuilder() apiruntime.SchemeBuilder {
	return seccompprofileapi.SchemeBuilder
}

// AllowedSyscallsChangedPredicate implements a update predicate function on SPOD's AllowedSyscalls changed.
type AllowedSyscallsChangedPredicate struct {
	predicate.Funcs
}

// Update implements default update event filter for checking SPOD's AllowedSyscalls change.
func (AllowedSyscallsChangedPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		return false
	}

	oldSpod, ok := e.ObjectOld.(*spodapi.SecurityProfilesOperatorDaemon)
	if !ok {
		return false
	}

	newSpod, ok := e.ObjectNew.(*spodapi.SecurityProfilesOperatorDaemon)
	if !ok {
		return false
	}

	if len(newSpod.Spec.Security.AllowedSyscalls) != len(oldSpod.Spec.Security.AllowedSyscalls) {
		return true
	}

	diff := make(map[string]int, len(newSpod.Spec.Security.AllowedSyscalls))
	for _, s := range newSpod.Spec.Security.AllowedSyscalls {
		diff[s]++
	}

	for _, s := range oldSpod.Spec.Security.AllowedSyscalls {
		if _, ok := diff[s]; !ok {
			return true
		}

		diff[s]--
		if diff[s] == 0 {
			delete(diff, s)
		}
	}

	return len(diff) != 0
}

// Setup adds a controller that reconciles seccomp profiles.
func (r *Reconciler) Setup(
	_ context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = util.NewEventRecorder(mgr, "profile")
	r.save = saveProfileOnDisk
	r.metrics = met
	r.nodeName = os.Getenv(config.NodeNameEnvKey)
	r.reader = mgr.GetAPIReader()

	// Register the regular reconciler to manage SeccompProfiles
	return ctrl.NewControllerManagedBy(mgr).
		Named("profile").
		For(&seccompprofileapi.SeccompProfile{}).
		// Profiles named "foo" and "foo.json" share a file, so a change of
		// one of them can change which one owns the file.
		Watches(
			&seccompprofileapi.SeccompProfile{},
			handler.EnqueueRequestsFromMapFunc(siblingRequests),
		).
		Watches(
			&spodapi.SecurityProfilesOperatorDaemon{},
			handler.EnqueueRequestsFromMapFunc(r.handleAllowedSyscallsChanged),
			builder.WithPredicates(AllowedSyscallsChangedPredicate{}),
		).
		Complete(r)
}

func (r *Reconciler) handleAllowedSyscallsChanged(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	spod, ok := obj.(*spodapi.SecurityProfilesOperatorDaemon)
	if !ok {
		r.log.Info("cannot handle allowedSyscalls changed for no SPOD objects")

		return []reconcile.Request{}
	}

	if len(spod.Spec.Security.AllowedSyscalls) == 0 {
		return []reconcile.Request{}
	}

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	seccompProfileList := &seccompprofileapi.SeccompProfileList{}
	if err := r.client.List(ctx, seccompProfileList); err != nil {
		r.log.Error(err, "cannot list seccomp profiles in the cluster")

		return []reconcile.Request{}
	}

	reconcileRequests := []reconcile.Request{}

	for i := range seccompProfileList.Items {
		sp := &seccompProfileList.Items[i]

		// Validate the merged syscalls, like validateProfile does, so that
		// syscalls inherited from base profiles are checked as well.
		merged := sp.DeepCopy()

		syscalls, err := r.resolveSyscallsForProfile(ctx, merged, merged.Spec.Syscalls, r.log, 0)
		if err != nil {
			r.log.Error(err, "cannot resolve syscalls of seccomp profile",
				"namespace", sp.GetNamespace(), "name", sp.GetName())

			continue
		}

		merged.Spec.Syscalls = syscalls

		if err := allowProfile(
			merged,
			spod.Spec.Security.AllowedSyscalls,
			spod.Spec.Security.AllowedSeccompActions,
		); err != nil {
			r.log.Info("deleting not allowed seccomp profile",
				"namespace", sp.GetNamespace(), "name", sp.GetName())

			if err := r.client.Delete(ctx, sp); err != nil {
				r.log.Error(err, "cannot delete not allowed seccomp profile")

				continue
			}

			reconcileRequests = append(reconcileRequests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      sp.GetName(),
					Namespace: sp.GetNamespace(),
				},
			})
		}
	}

	return reconcileRequests
}

// Healthz is the liveness probe endpoint of the controller.
func (r *Reconciler) Healthz(*http.Request) error {
	return r.checkSeccomp()
}

// checkSeccomp verifies if the seccomp is supported by the node.
func (r *Reconciler) checkSeccomp() error {
	if !seccomp.IsSupported() {
		err := fmt.Errorf("node %q: %w", r.nodeName, errSeccompNotSupported)

		if r.record != nil {
			r.reportError(
				util.EventNode(r.nodeName), reasonSeccompNotSupported, util.EventActionInstall, err,
			)
		}

		return err
	}

	return nil
}

// Security Profiles Operator RBAC permissions to manage SeccompProfile
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/finalizers,verbs=delete;get;update;patch

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;get;patch;update
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch;update

// OpenShift ... This is ignored in other distros
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security.openshift.io,namespace="security-profiles-operator",resourceNames=privileged,resources=securitycontextconstraints,verbs=use

// Reconcile reconciles a SeccompProfile.
func (r *Reconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	if err := r.checkSeccomp(); err != nil {
		logger.Error(err, "profile not added")
		// Do not requeue (will be requeued if a change to the object is
		// observed, or after the usually very long reconcile timeout
		// configured for the controller manager)
		return reconcile.Result{}, nil
	}

	seccompProfile := &seccompprofileapi.SeccompProfile{}
	if err := r.client.Get(ctx, req.NamespacedName, seccompProfile); err != nil {
		// Expected to find a SeccompProfile, return an error and requeue
		if util.IgnoreNotFound(err) == nil {
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("%w: %w", common.ErrGetProfile, err)
	}

	return r.reconcileSeccompProfile(ctx, seccompProfile, logger)
}

func (r *Reconciler) mergeBaseProfile(
	ctx context.Context, sp *seccompprofileapi.SeccompProfile, l logr.Logger,
) (*seccompprofileapi.SeccompProfile, error) {
	// Recursively resolve the syscalls
	finalSyscalls, err := r.resolveSyscallsForProfile(ctx, sp, sp.Spec.Syscalls, l, 0)
	if err != nil {
		return nil, fmt.Errorf("resolve syscalls: %w", err)
	}

	// Update the final syscalls in the profile for visibility
	scBytes, err := json.Marshal(finalSyscalls)
	if err != nil {
		return nil, fmt.Errorf("marshal syscalls to JSON: %w", err)
	}

	jsonSyscalls := string(scBytes)

	const key = "syscalls"
	if sp.Annotations[key] != jsonSyscalls {
		l.Info("Updating syscall annotations", "profile", sp.Name)

		if sp.Annotations == nil {
			sp.Annotations = make(map[string]string)
		}

		sp.Annotations[key] = jsonSyscalls

		if err := r.client.Update(ctx, sp); err != nil {
			return nil, fmt.Errorf("update seccomp profile annotations: %w", err)
		}
	}

	sp.Spec.Syscalls = finalSyscalls

	return sp, nil
}

// resolveSyscallsForProfile recursively resolves the syscalls for base
// profiles up to a depth level of 15 is also caches the results when pulling
// from OCI artifacts.
func (r *Reconciler) resolveSyscallsForProfile(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	inputSyscalls []seccompprofileapi.Syscall,
	l logr.Logger,
	level uint8,
) ([]seccompprofileapi.Syscall, error) {
	const maxLevel = 15
	if level >= maxLevel {
		return nil, fmt.Errorf(
			"max recursion level of %d is reached for resolving base profiles",
			maxLevel,
		)
	}

	baseProfileName := sp.Spec.BaseProfileName
	if baseProfileName == "" {
		// No base profile at all
		return inputSyscalls, nil
	}

	l.Info("Resolving syscalls for profile", "recursion", level)

	var baseProfile *seccompprofileapi.SeccompProfile

	if after, ok := strings.CutPrefix(baseProfileName, config.OCIProfilePrefix); ok {
		// Pull remote base profile from an OCI artifact registry
		from := after

		item := r.baseProfiles.Get(from)
		if item != nil {
			l.Info("Using cached base profile", "baseProfile", from)

			baseProfile = item.Value()
		} else {
			spod, err := r.GetSPOD(ctx, r.client)
			if err != nil {
				return nil, fmt.Errorf("retrieving the SPOD configuration: %w", err)
			}

			if spod.Spec.Security.AllowedIdentityRegexp == "" {
				spod.Spec.Security.AllowedIdentityRegexp = allowedAllRegexp
			}

			if spod.Spec.Security.AllowedOidcIssuerRegexp == "" {
				spod.Spec.Security.AllowedOidcIssuerRegexp = allowedAllRegexp
			}

			pullOpts := &artifact.PullOptions{
				DisableSignatureVerification: ptr.Deref(
					spod.Spec.Security.DisableOCIArtifactSignatureVerification,
					false,
				),
				AllowedIdentityRegexp:   spod.Spec.Security.AllowedIdentityRegexp,
				AllowedOidcIssuerRegexp: spod.Spec.Security.AllowedOidcIssuerRegexp,
				// A base profile bigger than what container runtimes accept
				// is of no use, and the registry must not decide how much
				// memory the daemon allocates on every node.
				MaxBlobSize: artifact.MaxRuntimeProfileSize,
			}
			l.Info(
				"Pulling base profile: "+from,
				"disableOCIArtifactSignatureVerification", pullOpts.DisableSignatureVerification,
				"allowedIdentityRegexp", pullOpts.AllowedIdentityRegexp,
				"allowedOidcIssuerRegexp", pullOpts.AllowedOidcIssuerRegexp,
				"maxBlobSize", pullOpts.MaxBlobSize,
			)

			// The pull is anonymous: the daemon has no registry credentials,
			// so base profiles have to be publicly readable.
			res, err := r.Pull(ctx, l, from, "", "", &v1.Platform{
				Architecture: runtime.GOARCH,
				OS:           runtime.GOOS,
			}, pullOpts)
			if err != nil {
				l.Error(err, "cannot pull base profile", "profile", baseProfileName)
				r.reportError(sp, reasonCannotPullProfile, util.EventActionInstall, err)

				return nil, fmt.Errorf("retrieve base profile %s from OCI registry: %w", from, err)
			}

			resType := r.PullResultType(res)
			if resType != artifact.PullResultTypeSeccompProfile {
				return nil, fmt.Errorf("pull result type %s is not a seccomp profile", resType)
			}

			baseProfile = r.PullResultSeccompProfile(res)
			r.baseProfiles.Set(from, baseProfile, ttlcache.DefaultTTL)

			l.Info(
				"Set remote base seccomp profile",
				"baseProfile", baseProfile.Name,
			)
		}
	} else {
		// Local base profile
		profile, err := r.ClientGetProfile(
			ctx, r.client, util.NamespacedName(baseProfileName, sp.GetNamespace()),
		)
		if err != nil {
			l.Error(err, "cannot retrieve base profile", "profile", baseProfileName)
			r.reportError(sp, reasonInvalidSeccompProfile, util.EventActionInstall, err)

			return nil, fmt.Errorf("merging base profile: %w", err)
		}

		baseProfile = profile

		l.Info(
			"Set remote base seccomp profile",
			"baseProfile", baseProfile.Name,
			"seccompProfile", sp.Name,
		)
	}

	newSyscalls, err := util.UnionSyscalls(baseProfile.Spec.Syscalls, inputSyscalls)
	if err != nil {
		return nil, fmt.Errorf("merging base profile syscalls: %w", err)
	}

	return r.resolveSyscallsForProfile(ctx, baseProfile, newSyscalls, l, level+1)
}

func (r *Reconciler) reconcileSeccompProfile(
	ctx context.Context, sp *seccompprofileapi.SeccompProfile, l logr.Logger,
) (reconcile.Result, error) {
	if sp == nil {
		return reconcile.Result{}, errSeccompProfileNil
	}

	profileName := sp.Name

	nodeStatus, err := nodestatus.NewForProfileOnNode(sp, r.client, r.nodeName)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot create nodeStatus: %w", err)
	}

	if !sp.GetDeletionTimestamp().IsZero() { // object is being deleted
		return r.reconcileDeletion(ctx, sp, nodeStatus)
	}

	l.Info("Merge possible base profile")

	outputProfile, err := r.mergeBaseProfile(ctx, sp, l)
	if err != nil {
		l.Error(err, "merge base profile")

		return reconcile.Result{RequeueAfter: common.Wait}, nil
	}

	l.Info("Validate profile")

	if err := r.validateProfile(ctx, outputProfile); err != nil {
		l.Error(err, "validate profile")
		r.reportError(sp, reasonProfileNotAllowed, util.EventActionInstall, err)

		return reconcile.Result{}, fmt.Errorf("validating profile: %w", err)
	}

	l.Info("Got profile content")

	profileContent, err := json.Marshal(outputProfile.Spec)
	if err != nil {
		l.Error(err, "cannot validate profile", "profile", profileName)
		r.reportError(sp, reasonInvalidSeccompProfile, util.EventActionInstall, err)

		return reconcile.Result{}, fmt.Errorf("cannot validate profile: %w", err)
	}

	profilePath := r.profilePath(sp)

	// The object is not being deleted
	created, _, err := common.EnsureNodeStatus(ctx, nodeStatus, l)
	if err != nil {
		return reconcile.Result{}, err
	}

	if created {
		return reconcile.Result{RequeueAfter: common.Wait}, nil
	}

	if !sp.IsReconcilable() {
		l.Info("Profile is partial or disabled, skipping")

		return reconcile.Result{}, nil
	}

	conflict, err := r.handleFileConflict(ctx, sp, nodeStatus, profilePath, profileContent, l)
	if err != nil {
		return reconcile.Result{}, err
	}

	if conflict {
		return reconcile.Result{RequeueAfter: fileConflictRetry}, nil
	}

	l.Info("Saving profile to disk")

	updated, err := r.save(profilePath, profileContent)
	if err != nil {
		l.Error(err, "cannot save profile into disk")
		r.reportError(sp, reasonCannotSaveProfile, util.EventActionInstall, err)

		return reconcile.Result{}, fmt.Errorf("cannot save profile into disk: %w", err)
	}

	if updated {
		evstr := "Successfully saved profile to disk on " + r.nodeName
		l.Info(evstr)
		r.metrics.IncSeccompProfileUpdate()
		r.record.Eventf(
			sp,
			nil,
			util.EventTypeNormal,
			reasonSavedProfile,
			util.EventActionInstall,
			"%s",
			evstr,
		)
	}

	l.Info("Checking node status")

	isAlreadyInstalled, getErr := nodeStatus.Matches(
		ctx,
		secprofnodestatusapi.ProfileStateInstalled,
	)
	if getErr != nil {
		l.Error(getErr, "couldn't get current status")

		return reconcile.Result{}, fmt.Errorf(
			"getting status for installed SeccompProfile: %w",
			getErr,
		)
	}

	if isAlreadyInstalled {
		l.Info("Already in the expected Installed state")

		return reconcile.Result{}, nil
	}

	l.Info("Set node status to installed")

	if err := nodeStatus.SetNodeStatus(
		ctx,
		secprofnodestatusapi.ProfileStateInstalled,
	); err != nil {
		l.Error(err, "cannot update node status")
		r.reportError(sp, common.ReasonCannotUpdateStatus, util.EventActionUpdate, err)

		return reconcile.Result{}, fmt.Errorf(
			"updating status in SeccompProfile reconciler: %w",
			err,
		)
	}

	l.Info(
		"Reconciled profile from SeccompProfile",
		"resource version", sp.GetResourceVersion(),
		"name", sp.GetName(),
	)

	return reconcile.Result{}, nil
}

func (r *Reconciler) reconcileDeletion(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	nsc *nodestatus.StatusClient,
) (reconcile.Result, error) {
	return common.ReconcileDeletion(
		ctx, sp, nsc, r.client, r.log, r.record,
		common.DeletionReasons{
			CannotUpdateProfile: reasonCannotUpdateProfile,
			CannotRemoveProfile: reasonCannotRemoveProfile,
			CannotUpdateStatus:  common.ReasonCannotUpdateStatus,
		},
		r.metrics.IncSeccompProfileError,
		func() (reconcile.Result, error) { return reconcile.Result{}, r.handleDeletion(ctx, sp) },
	)
}

// fileConflictRetry is the time after which a profile whose file is owned by
// another profile is checked again, so that it gets installed once the other
// profile is gone.
const fileConflictRetry = time.Minute

// errProfileFileConflict is returned if the file of a profile is owned by
// another profile.
var errProfileFileConflict = errors.New("profile file is already used by another profile")

// siblingName returns the name of the other profile which can share the file
// of a profile with the provided name. The file of a profile gets a ".json"
// suffix unless its name already has it, so "foo" and "foo.json" share
// operator/foo.json.
func siblingName(name string) string {
	if trimmed, ok := strings.CutSuffix(name, seccompprofileapi.ExtJSON); ok {
		return trimmed
	}

	return name + seccompprofileapi.ExtJSON
}

// siblingRequests enqueues the profile which can share the file of obj.
func siblingRequests(_ context.Context, obj client.Object) []reconcile.Request {
	name := siblingName(obj.GetName())
	if name == "" {
		return nil
	}

	return []reconcile.Request{{NamespacedName: util.NamespacedName(name, obj.GetNamespace())}}
}

// sibling returns the other profile which is stored in the same file as sp,
// if there is one.
func sibling(
	ctx context.Context, reader client.Reader, sp *seccompprofileapi.SeccompProfile,
) (*seccompprofileapi.SeccompProfile, bool, error) {
	name := siblingName(sp.GetName())
	if name == "" {
		return nil, false, nil
	}

	other := &seccompprofileapi.SeccompProfile{}
	if err := reader.Get(ctx, util.NamespacedName(name, sp.GetNamespace()), other); err != nil {
		if util.IgnoreNotFound(err) == nil {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("looking up profile %s: %w", name, err)
	}

	if other.GetProfileFile() != sp.GetProfileFile() {
		return nil, false, nil
	}

	return other, true, nil
}

// fileOwner returns the name of the other profile which is stored in the same
// file as sp and owns it, or an empty string. A profile which is being deleted
// or which is not installed, because it is disabled or partial, owns nothing.
// Otherwise the profile created first owns the file, and the name decides on
// a tie.
func fileOwner(
	ctx context.Context, reader client.Reader, sp *seccompprofileapi.SeccompProfile,
) (string, error) {
	other, found, err := sibling(ctx, reader, sp)
	if err != nil || !found {
		return "", err
	}

	if !other.GetDeletionTimestamp().IsZero() || !other.IsReconcilable() {
		return "", nil
	}

	if sp.IsReconcilable() && sp.GetDeletionTimestamp().IsZero() && !ownsFileBefore(other, sp) {
		return "", nil
	}

	return other.GetName(), nil
}

// fileDiffers returns true if the file at filePath does not hold content.
func fileDiffers(filePath string, content []byte) bool {
	existing, err := os.ReadFile(filePath)
	if err != nil {
		return true
	}

	return !bytes.Equal(existing, content)
}

// ownsFileBefore returns true if profile a takes precedence over profile b
// for a file they share.
func ownsFileBefore(a, b *seccompprofileapi.SeccompProfile) bool {
	ta, tb := a.GetCreationTimestamp(), b.GetCreationTimestamp()
	if !ta.Equal(&tb) {
		return ta.Before(&tb)
	}

	return a.GetName() < b.GetName()
}

// handleFileConflict marks the profile as failed if another profile owns its
// file on disk. It returns true if there is a conflict.
func (r *Reconciler) handleFileConflict(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	nodeStatus *nodestatus.StatusClient,
	profilePath string,
	content []byte,
	l logr.Logger,
) (bool, error) {
	// Usually there is no other profile with the same file, which the cache
	// shows without asking the API server on every reconcile. A profile
	// which is missing from the cache only matters if the file changes.
	_, cached, err := sibling(ctx, r.client, sp)
	if err != nil {
		return false, err
	}

	if !cached && !fileDiffers(profilePath, content) {
		return false, nil
	}

	owner, err := fileOwner(ctx, r.apiReader(), sp)
	if err != nil || owner == "" {
		return false, err
	}

	conflictErr := fmt.Errorf(
		"%w: %s is stored as %s like %s, rename one of them",
		errProfileFileConflict, sp.GetName(), sp.GetProfileFile(), owner,
	)
	l.Error(conflictErr, "Not saving profile")
	r.reportError(sp, reasonProfileFileConflict, util.EventActionInstall, conflictErr)

	if err := nodeStatus.SetNodeStatus(ctx, secprofnodestatusapi.ProfileStateError); err != nil {
		return true, fmt.Errorf("setting node status to error: %w", err)
	}

	return true, nil
}

func (r *Reconciler) handleDeletion(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
) error {
	// The file belongs to another profile, which must keep it. This is also
	// the case if the other profile lost the file to this one, because it
	// takes the file over once this profile is gone.
	owner, err := fileOwner(ctx, r.apiReader(), sp)
	if err != nil {
		return err
	}

	if owner != "" {
		return nil
	}

	profilePath := r.profilePath(sp)

	err = os.Remove(profilePath)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("removing profile from host: %w", err)
	}

	r.log.Info("removed profile", "path", profilePath)
	r.metrics.IncSeccompProfileDelete()

	return nil
}

func (r *Reconciler) validateProfile(
	ctx context.Context,
	profile *seccompprofileapi.SeccompProfile,
) error {
	spod, err := r.GetSPOD(ctx, r.client)
	if err != nil {
		return fmt.Errorf("retrieving the SPOD configuration: %w", err)
	}

	if len(spod.Spec.Security.AllowedSyscalls) > 0 {
		return allowProfile(
			profile,
			spod.Spec.Security.AllowedSyscalls,
			spod.Spec.Security.AllowedSeccompActions,
		)
	}

	return nil
}

func saveProfileOnDisk(fileName string, content []byte) (updated bool, err error) {
	if err := os.MkdirAll(path.Dir(fileName), dirPermissionMode); err != nil {
		return false, fmt.Errorf("%w: %w", errCreatingOperatorDir, err)
	}

	existingContent, err := os.ReadFile(fileName)
	if err == nil && bytes.Equal(existingContent, content) {
		return false, nil
	}

	if err := util.WriteFileAtomic(fileName, content, filePermissionMode); err != nil {
		return false, fmt.Errorf("%w: %w", errSavingProfile, err)
	}

	return true, nil
}

func allowProfile(
	profile *seccompprofileapi.SeccompProfile,
	allowedSyscalls []string,
	allowedActions []seccompprofileapi.Action,
) error {
	syscalls := map[seccompprofileapi.Action]map[string]bool{}
	for _, call := range profile.Spec.Syscalls {
		if _, ok := syscalls[call.Action]; !ok {
			syscalls[call.Action] = map[string]bool{}
		}

		for _, name := range call.Names {
			syscalls[call.Action][name] = true
		}
	}

	allAllowedActions := []seccompprofileapi.Action{
		seccompprofileapi.ActAllow,
		seccompprofileapi.ActLog,
		seccompprofileapi.ActTrace,
		seccompprofileapi.ActNotify,
	}
	if len(allowedActions) == 0 {
		allowedActions = allAllowedActions
	}

	for _, allowedAction := range allowedActions {
		if !slices.Contains(allAllowedActions, allowedAction) {
			return fmt.Errorf("%w: %s", errForbiddenAction, allowedAction)
		}
	}

	// Hoisted out of the loop: a linear scan per syscall makes this O(n*m),
	// and handleAllowedSyscallsChanged runs it over every profile in the
	// cluster whenever the SPOD changes.
	allowed := sets.New(allowedSyscalls...)

	for _, action := range allowedActions {
		if actionCalls, ok := syscalls[action]; ok {
			for call := range actionCalls {
				if !allowed.Has(call) {
					return fmt.Errorf("%w: %s", errForbiddenSyscall, call)
				}
			}
		}

		if profile.Spec.DefaultAction == action && len(allowedSyscalls) > 0 {
			return errForbiddenProfile
		}
	}

	return nil
}
