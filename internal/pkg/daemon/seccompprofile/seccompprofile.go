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
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.podman.io/common/pkg/seccomp"
	corev1 "k8s.io/api/core/v1"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
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
	"sigs.k8s.io/security-profiles-operator/internal/pkg/seccompcheck"
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

	// errInvalidBaseProfile marks base profile errors which retrying cannot
	// fix, only a change of the profiles can.
	errInvalidBaseProfile = seccompcheck.ErrInvalidBaseProfile

	// errMissingKey is returned if the Secret or ConfigMap of the signature
	// verification lacks the selected key.
	errMissingKey = errors.New("missing key")

	// errOfflineWithoutTrustedRoot is returned if the signature verification
	// is offline without a trusted root: the daemon has no TUF cache which
	// survives a restart to take the trusted root from.
	errOfflineWithoutTrustedRoot = errors.New(
		"spec.security.signatureVerification.offline requires trustedRootConfigMapRef",
	)
)

// syscallsAnnotation is the annotation which shows the syscalls of a profile
// merged with the ones of its base profiles.
const syscallsAnnotation = "syscalls"

// syscallsAnnotationKey returns the key of the annotation for the merged
// syscalls. A base profile from an OCI registry is pulled for the architecture
// of the node, so the result can differ between the nodes of a cluster with
// mixed architectures. Those results get one annotation per architecture,
// otherwise the nodes would overwrite each other forever.
func syscallsAnnotationKey(archSpecific bool) string {
	if archSpecific {
		return syscallsAnnotation + "-" + runtime.GOARCH
	}

	return syscallsAnnotation
}

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
	// namespace is the namespace of the operator, which holds the key and
	// the trusted root for the signature verification of base profiles.
	namespace string
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
	r.errorReporter().Report(obj, reason, action, err.Error())
}

// Name returns the name of the controller.
func (r *Reconciler) Name() string {
	return "seccomp-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *Reconciler) SchemeBuilder() apiruntime.SchemeBuilder {
	return seccompprofileapi.SchemeBuilder
}

// Setup adds a controller that reconciles seccomp profiles.
func (r *Reconciler) Setup(
	ctx context.Context,
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

	namespace, err := config.TryToGetOperatorNamespace()
	if err != nil {
		return fmt.Errorf("getting the operator namespace: %w", err)
	}

	r.namespace = namespace

	removeStaleTempFiles(r.log, config.ProfilesRootPath())

	if err := mgr.GetFieldIndexer().IndexField(
		ctx, &seccompprofileapi.SeccompProfile{}, baseProfileIndex, indexBaseProfile,
	); err != nil {
		return fmt.Errorf("creating base profile index: %w", err)
	}

	// Register the regular reconciler to manage SeccompProfiles
	return ctrl.NewControllerManagedBy(mgr).
		Named("profile").
		For(
			&seccompprofileapi.SeccompProfile{},
			builder.WithPredicates(predicate.Or(profileChangedPredicate, profileResyncPredicate)),
		).
		// Profiles named "foo" and "foo.json" share a file, so a change of
		// one of them can change which one owns the file. Ownership depends
		// on the spec, the partial label and the deletion only.
		Watches(
			&seccompprofileapi.SeccompProfile{},
			handler.EnqueueRequestsFromMapFunc(siblingRequests),
			builder.WithPredicates(profileChangedPredicate),
		).
		// A profile whose base profile is missing or invalid is not retried
		// on its own, so a change of the base profile has to wake it up.
		Watches(
			&seccompprofileapi.SeccompProfile{},
			handler.EnqueueRequestsFromMapFunc(r.derivedProfileRequests),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Watches(
			&spodapi.SecurityProfilesOperatorDaemon{},
			handler.EnqueueRequestsFromMapFunc(r.handleAllowedSyscallsChanged),
			builder.WithPredicates(seccompcheck.AllowListChangedPredicate{}),
		).
		Complete(r)
}

// profileChangedPredicate passes the changes of a profile which the node has
// to act on. Without it every node reconciles every profile on each write of
// its status by the manager, of the syscalls annotation and of the finalizers
// of the other nodes, and reads the profile file each time.
//
// An earlier version of this filter (8c13a1ee6) was reverted (e6c88a7d6) on
// the suspicion of breaking the e2e tests, which passed on a retry later. It
// used WithEventFilter, which also filtered the SPOD and base profile watches.
// This one only applies to the watches of the profile itself, where nothing
// else is lost:
//   - The API server bumps the generation when it sets the deletion
//     timestamp, so a deletion passes.
//   - Creation and removal always pass, which covers the initial list after a
//     restart of the daemon and a sibling profile going away.
//   - A partial profile being merged, and the status label added by the
//     node status client, are label changes.
//   - Everything which waits for a change of the metadata, like pods which
//     still use a disabled or deleted profile, or the node status which was
//     just created, requeues itself after a delay.
var profileChangedPredicate = predicate.Or(
	predicate.GenerationChangedPredicate{},
	predicate.LabelChangedPredicate{},
)

// profileResyncPredicate passes the periodic resyncs of the daemon cache,
// which carry an unchanged resource version. They reinstall a profile file
// which got removed or changed on the host.
var profileResyncPredicate = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		return e.ObjectOld != nil && e.ObjectNew != nil &&
			e.ObjectOld.GetResourceVersion() == e.ObjectNew.GetResourceVersion()
	},
}

// handleAllowedSyscallsChanged enqueues every profile when the allow lists of
// the SPOD change, so that each one gets validated again: the ones which got
// rejected before get installed if they are allowed now, and the ones which
// are not allowed anymore get rejected. Deleting the profiles which the new
// allow lists reject is left to the manager, which does it once for the
// cluster.
func (r *Reconciler) handleAllowedSyscallsChanged(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	if _, ok := obj.(*spodapi.SecurityProfilesOperatorDaemon); !ok {
		r.log.Info("cannot handle allowedSyscalls changed for no SPOD objects")

		return []reconcile.Request{}
	}

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	seccompProfileList := &seccompprofileapi.SeccompProfileList{}
	if err := r.client.List(ctx, seccompProfileList); err != nil {
		r.log.Error(err, "cannot list seccomp profiles in the cluster")

		return []reconcile.Request{}
	}

	reconcileRequests := make([]reconcile.Request, 0, len(seccompProfileList.Items))
	for i := range seccompProfileList.Items {
		reconcileRequests = append(reconcileRequests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&seccompProfileList.Items[i]),
		})
	}

	return reconcileRequests
}

// removeStaleTempFiles removes the temporary files of interrupted profile
// writes. They live next to the profiles, which are stored in a directory per
// namespace below root.
func removeStaleTempFiles(l logr.Logger, root string) {
	common.RemoveStaleTempFiles(l, root)

	entries, err := os.ReadDir(root)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			l.Error(err, "Cannot list profile directories", "dir", root)
		}

		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			common.RemoveStaleTempFiles(l, filepath.Join(root, entry.Name()))
		}
	}
}

// baseProfileIndex indexes the profiles by the name of their local base
// profile.
const baseProfileIndex = "spec.baseProfileName"

func indexBaseProfile(obj client.Object) []string {
	sp, ok := obj.(*seccompprofileapi.SeccompProfile)
	if !ok || sp.Spec.BaseProfileName == "" ||
		strings.HasPrefix(sp.Spec.BaseProfileName, config.OCIProfilePrefix) {
		return nil
	}

	return []string{sp.Spec.BaseProfileName}
}

// derivedProfileRequests enqueues the profiles which use obj as their base
// profile, directly or through other base profiles. A profile further down the
// chain has to be enqueued as well: the profiles in between do not change
// their generation when they get installed, so this watch would not see them.
func (r *Reconciler) derivedProfileRequests(
	ctx context.Context, obj client.Object,
) []reconcile.Request {
	var requests []reconcile.Request

	seen := map[string]bool{obj.GetName(): true}
	bases := []string{obj.GetName()}

	for len(bases) > 0 {
		base := bases[0]
		bases = bases[1:]

		list := &seccompprofileapi.SeccompProfileList{}
		if err := r.client.List(
			ctx, list,
			client.InNamespace(obj.GetNamespace()),
			client.MatchingFields{baseProfileIndex: base},
		); err != nil {
			r.log.Error(err, "cannot list seccomp profiles to find derived profiles")

			return requests
		}

		for i := range list.Items {
			name := list.Items[i].GetName()
			if seen[name] {
				continue
			}

			seen[name] = true
			bases = append(bases, name)
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(&list.Items[i]),
			})
		}
	}

	return requests
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
// The daemon updates the finalizers and labels and patches the annotations of
// the profiles, and the profile recorder creates recorded SeccompProfiles. The
// profile status is written by the manager. The finalizers subresource allows
// the node statuses to block the deletion of their owner profile.
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/finalizers,verbs=get;update;patch

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
//
// The public key and the trusted root for the signature verification of base
// profiles, which are read uncached from the operator namespace:
// +kubebuilder:rbac:groups=core,namespace="security-profiles-operator",resources=secrets;configmaps,verbs=get

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
	finalSyscalls, archSpecific, err := r.resolveSyscallsForProfile(
		ctx, sp, sp.Spec.Syscalls, l, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve syscalls: %w", err)
	}

	if err := r.annotateSyscalls(ctx, sp, finalSyscalls, archSpecific, l); err != nil {
		return nil, err
	}

	merged := sp.DeepCopy()
	merged.Spec.Syscalls = finalSyscalls

	return merged, nil
}

// annotateSyscalls shows the merged syscalls in an annotation of the profile,
// because the syscalls of the base profiles are hidden from the user
// otherwise.
func (r *Reconciler) annotateSyscalls(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	syscalls []seccompprofileapi.Syscall,
	archSpecific bool,
	l logr.Logger,
) error {
	scBytes, err := json.Marshal(syscalls)
	if err != nil {
		return fmt.Errorf("marshal syscalls to JSON: %w", err)
	}

	key := syscallsAnnotationKey(archSpecific)
	value := string(scBytes)

	// The annotation of the other kind is stale: the base profiles changed,
	// or the shared one got written by a version which put every result
	// into it.
	staleKey := syscallsAnnotationKey(!archSpecific)
	_, hasStale := sp.GetAnnotations()[staleKey]

	if sp.GetAnnotations()[key] == value && !hasStale {
		return nil
	}

	l.Info("Updating syscall annotations", "profile", sp.Name, "annotation", key)

	patch := client.MergeFrom(sp.DeepCopy())

	if sp.Annotations == nil {
		sp.Annotations = make(map[string]string)
	}

	sp.Annotations[key] = value
	delete(sp.Annotations, staleKey)

	// Patching only the annotations does not conflict with the other nodes
	// updating the profile at the same time.
	if err := r.client.Patch(ctx, sp, patch); err != nil {
		return fmt.Errorf("update seccomp profile annotations: %w", err)
	}

	return nil
}

// resolveSyscallsForProfile recursively resolves the syscalls for base
// profiles up to a depth level of 15 is also caches the results when pulling
// from OCI artifacts. archSpecific is true if an OCI base profile got used,
// which is pulled for the architecture of the node.
func (r *Reconciler) resolveSyscallsForProfile(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	inputSyscalls []seccompprofileapi.Syscall,
	l logr.Logger,
	level uint8,
) (syscalls []seccompprofileapi.Syscall, archSpecific bool, err error) {
	const maxLevel = seccompcheck.MaxBaseProfileDepth
	if level >= maxLevel {
		return nil, false, fmt.Errorf(
			"%w: max recursion level of %d is reached for resolving base profiles",
			errInvalidBaseProfile, maxLevel,
		)
	}

	baseProfileName := sp.Spec.BaseProfileName
	if baseProfileName == "" {
		// No base profile at all
		return inputSyscalls, false, nil
	}

	l.Info("Resolving syscalls for profile", "recursion", level)

	var baseProfile *seccompprofileapi.SeccompProfile

	if from, ok := strings.CutPrefix(baseProfileName, config.OCIProfilePrefix); ok {
		archSpecific = true

		if item := r.baseProfiles.Get(from); item != nil {
			l.Info("Using cached base profile", "baseProfile", from)

			baseProfile = item.Value()
		} else {
			baseProfile, err = r.pullBaseProfile(ctx, sp, from, l)
			if err != nil {
				return nil, false, err
			}
		}
	} else {
		// Local base profile
		profile, err := r.ClientGetProfile(
			ctx, r.client, util.NamespacedName(baseProfileName, sp.GetNamespace()),
		)
		if err != nil {
			if util.IgnoreNotFound(err) == nil {
				// derivedProfileRequests enqueues the profile again once
				// the base profile gets created.
				return nil, false, fmt.Errorf(
					"%w: %s not found", errInvalidBaseProfile, baseProfileName,
				)
			}

			return nil, false, fmt.Errorf("retrieving base profile %s: %w", baseProfileName, err)
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
		return nil, false, fmt.Errorf(
			"%w: merging base profile syscalls: %w", errInvalidBaseProfile, err,
		)
	}

	syscalls, baseArchSpecific, err := r.resolveSyscallsForProfile(
		ctx, baseProfile, newSyscalls, l, level+1,
	)

	return syscalls, archSpecific || baseArchSpecific, err
}

// pullBaseProfile pulls the base profile of sp from the OCI artifact registry
// and caches it.
func (r *Reconciler) pullBaseProfile(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	from string,
	l logr.Logger,
) (*seccompprofileapi.SeccompProfile, error) {
	spod, err := r.GetSPOD(ctx, r.client, r.namespace)
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

	// The signature verification settings are meant for private base
	// profiles. The official ones are always verified against the official
	// signers, so that a key or an identity for the private base profiles
	// does not break them.
	if !pullOpts.DisableSignatureVerification && !artifact.IsOfficialArtifact(from) {
		cleanup, err := r.applySignatureVerification(
			ctx, spod.Spec.Security.SignatureVerification, pullOpts, l,
		)
		if err != nil {
			r.reportError(sp, reasonCannotPullProfile, util.EventActionInstall, err)

			return nil, fmt.Errorf("configuring the signature verification: %w", err)
		}

		defer cleanup()
	}

	// The official repositories get verified against the official
	// signers while the regexps are left at the default. An exact identity
	// or issuer only replaces its own part.
	identity, issuer := pullOpts.Signer(from)
	l.Info(
		"Pulling base profile: "+from,
		"disableOCIArtifactSignatureVerification", pullOpts.DisableSignatureVerification,
		"allowedIdentityRegexp", pullOpts.AllowedIdentityRegexp,
		"allowedOidcIssuerRegexp", pullOpts.AllowedOidcIssuerRegexp,
		"verifiedIdentityRegexp", identity,
		"verifiedOidcIssuerRegexp", issuer,
		"allowedIdentity", pullOpts.CertIdentity,
		"allowedOidcIssuer", pullOpts.CertOidcIssuer,
		"publicKey", pullOpts.KeyRef != "",
		"trustedRoot", pullOpts.TrustedRootPath != "",
		"offline", pullOpts.Offline,
		"maxBlobSize", pullOpts.MaxBlobSize,
	)

	// No credentials are passed: the pull only uses a docker config in the
	// daemon container, which is usually missing, so base profiles have to
	// be publicly readable.
	res, err := r.Pull(ctx, l, from, "", "", &v1.Platform{
		Architecture: runtime.GOARCH,
		OS:           runtime.GOOS,
	}, pullOpts)
	if err != nil {
		l.Error(err, "cannot pull base profile", "profile", sp.Spec.BaseProfileName)
		r.reportError(sp, reasonCannotPullProfile, util.EventActionInstall, err)

		return nil, fmt.Errorf("retrieve base profile %s from OCI registry: %w", from, err)
	}

	resType := r.PullResultType(res)
	if resType != artifact.PullResultTypeSeccompProfile {
		return nil, fmt.Errorf(
			"%w: pull result type %s is not a seccomp profile", errInvalidBaseProfile, resType,
		)
	}

	baseProfile := r.PullResultSeccompProfile(res)
	r.baseProfiles.Set(from, baseProfile, ttlcache.DefaultTTL)

	l.Info(
		"Set remote base seccomp profile",
		"baseProfile", baseProfile.Name,
	)

	return baseProfile, nil
}

// applySignatureVerification copies the signature verification settings of
// the SPOD into the pull options. The public key and the trusted root are read
// from the operator namespace and written to temporary files for cosign,
// which the returned function removes.
func (r *Reconciler) applySignatureVerification(
	ctx context.Context,
	sv *spodapi.SPODSignatureVerification,
	opts *artifact.PullOptions,
	l logr.Logger,
) (cleanup func(), err error) {
	var files []string

	cleanup = func() {
		for _, file := range files {
			if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
				l.Error(err, "Cannot remove temporary signature verification file", "file", file)
			}
		}
	}

	if sv == nil {
		return cleanup, nil
	}

	// Rejected by the API server as well, but not by the ones which do not
	// evaluate the CEL rules of the CRD. The TUF cache of the daemon lives in
	// an emptyDir, so offline verification needs an explicit trusted root.
	if ptr.Deref(sv.Offline, false) && sv.TrustedRootConfigMapRef == nil {
		return nil, errOfflineWithoutTrustedRoot
	}

	opts.CertIdentity = sv.AllowedIdentity
	opts.CertOidcIssuer = sv.AllowedOidcIssuer
	opts.Offline = ptr.Deref(sv.Offline, false)

	if ref := sv.PublicKeySecretRef; ref != nil {
		key, err := r.secretKey(ctx, ref)
		if err != nil {
			return nil, err
		}

		file, err := writeTempFile("spo-cosign-*.pub", key)
		if err != nil {
			return nil, fmt.Errorf("writing the public key: %w", err)
		}

		files = append(files, file)
		opts.KeyRef = file
	}

	if ref := sv.TrustedRootConfigMapRef; ref != nil {
		root, err := r.configMapKey(ctx, ref)
		if err != nil {
			cleanup()

			return nil, err
		}

		file, err := writeTempFile("spo-trusted-root-*.json", root)
		if err != nil {
			cleanup()

			return nil, fmt.Errorf("writing the trusted root: %w", err)
		}

		files = append(files, file)
		opts.TrustedRootPath = file
	}

	return cleanup, nil
}

// secretKey returns the value of the selected key of a Secret in the operator
// namespace.
func (r *Reconciler) secretKey(
	ctx context.Context, ref *corev1.SecretKeySelector,
) ([]byte, error) {
	secret := &corev1.Secret{}

	// The Secret is read uncached, so that the daemon neither needs to list
	// nor to watch Secrets.
	if err := r.apiReader().Get(
		ctx, client.ObjectKey{Namespace: r.namespace, Name: ref.Name}, secret,
	); err != nil {
		return nil, fmt.Errorf(
			"getting the public key Secret %s/%s: %w",
			r.namespace,
			ref.Name,
			err,
		)
	}

	value, ok := secret.Data[ref.Key]
	if !ok || len(value) == 0 {
		return nil, fmt.Errorf(
			"%w: key %s in Secret %s/%s",
			errMissingKey,
			ref.Key,
			r.namespace,
			ref.Name,
		)
	}

	return value, nil
}

// configMapKey returns the value of the selected key of a ConfigMap in the
// operator namespace.
func (r *Reconciler) configMapKey(
	ctx context.Context, ref *corev1.ConfigMapKeySelector,
) ([]byte, error) {
	cm := &corev1.ConfigMap{}

	if err := r.apiReader().Get(
		ctx, client.ObjectKey{Namespace: r.namespace, Name: ref.Name}, cm,
	); err != nil {
		return nil, fmt.Errorf(
			"getting the trusted root ConfigMap %s/%s: %w",
			r.namespace,
			ref.Name,
			err,
		)
	}

	if value, ok := cm.Data[ref.Key]; ok && value != "" {
		return []byte(value), nil
	}

	if value, ok := cm.BinaryData[ref.Key]; ok && len(value) > 0 {
		return value, nil
	}

	return nil, fmt.Errorf(
		"%w: key %s in ConfigMap %s/%s",
		errMissingKey,
		ref.Key,
		r.namespace,
		ref.Name,
	)
}

// writeTempFile writes content to a new temporary file and returns its path.
func writeTempFile(pattern string, content []byte) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("creating temporary file: %w", err)
	}

	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())

		return "", fmt.Errorf("writing temporary file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(f.Name())

		return "", fmt.Errorf("closing temporary file: %w", err)
	}

	return f.Name(), nil
}

func (r *Reconciler) reconcileSeccompProfile(
	ctx context.Context, sp *seccompprofileapi.SeccompProfile, l logr.Logger,
) (reconcile.Result, error) {
	if sp == nil {
		return reconcile.Result{}, errSeccompProfileNil
	}

	nodeStatus, err := nodestatus.NewForProfileOnNode(sp, r.client, r.nodeName)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot create nodeStatus: %w", err)
	}

	if !sp.GetDeletionTimestamp().IsZero() { // object is being deleted
		return r.reconcileDeletion(ctx, sp, nodeStatus, l)
	}

	// The object is not being deleted
	if res, stop, err := common.EnsureNodeStatusOrRequeue(ctx, nodeStatus, l); stop {
		return res, err
	}

	if !sp.IsReconcilable() {
		if sp.IsDisabled() && !sp.IsPartial() {
			return r.reconcileDisabled(ctx, sp, nodeStatus, l)
		}

		l.Info("Profile is partial, skipping")

		return reconcile.Result{}, nil
	}

	profileContent, err := r.buildProfileContent(ctx, sp, nodeStatus, l)
	if profileContent == nil || err != nil {
		return reconcile.Result{}, err
	}

	if res, err := r.writeProfile(
		ctx,
		sp,
		nodeStatus,
		profileContent,
		l,
	); res.RequeueAfter > 0 ||
		err != nil {
		return res, err
	}

	l.Info("Checking node status")

	changed, err := common.MarkInstalled(ctx, sp, nodeStatus, l, r.errorReporter())
	if err != nil {
		return reconcile.Result{}, fmt.Errorf(
			"updating status in SeccompProfile reconciler: %w",
			err,
		)
	}

	if changed {
		l.Info(
			"Reconciled profile from SeccompProfile",
			"resource version", sp.GetResourceVersion(),
			"name", sp.GetName(),
		)
	}

	return reconcile.Result{}, nil
}

// buildProfileContent merges the base profiles into the profile, validates
// the result and returns it as the content of the profile file. A profile
// which cannot be installed until it, one of its base profiles or the SPOD
// changes gets rejected, which returns nil content without an error.
func (r *Reconciler) buildProfileContent(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) ([]byte, error) {
	l.Info("Merge possible base profile")

	outputProfile, err := r.mergeBaseProfile(ctx, sp, l)
	if err != nil {
		if errors.Is(err, errInvalidBaseProfile) {
			return nil, r.rejectProfile(
				ctx, sp, nodeStatus, reasonInvalidSeccompProfile, err, l,
			)
		}

		// For example the registry of an OCI base profile is unreachable,
		// which is retried with backoff.
		l.Error(err, "merge base profile")

		return nil, fmt.Errorf("merging base profile: %w", err)
	}

	l.Info("Validate profile")

	if err := r.validateProfile(ctx, outputProfile); err != nil {
		if seccompcheck.NotAllowed(err) {
			return nil, r.rejectProfile(
				ctx, sp, nodeStatus, reasonProfileNotAllowed, err, l,
			)
		}

		l.Error(err, "validate profile")

		return nil, fmt.Errorf("validating profile: %w", err)
	}

	l.Info("Got profile content")

	profileContent, err := json.Marshal(outputProfile.Spec)
	if err != nil {
		l.Error(err, "cannot validate profile", "profile", sp.GetName())
		r.reportError(sp, reasonInvalidSeccompProfile, util.EventActionInstall, err)

		return nil, fmt.Errorf("cannot validate profile: %w", err)
	}

	return profileContent, nil
}

// writeProfile writes the profile file unless another profile owns it, in
// which case the result requeues the profile.
func (r *Reconciler) writeProfile(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	nodeStatus *nodestatus.StatusClient,
	profileContent []byte,
	l logr.Logger,
) (reconcile.Result, error) {
	profilePath := r.profilePath(sp)

	conflict, upToDate, err := r.handleFileConflict(
		ctx,
		sp,
		nodeStatus,
		profilePath,
		profileContent,
		l,
	)
	if err != nil {
		return reconcile.Result{}, err
	}

	if conflict {
		return reconcile.Result{RequeueAfter: fileConflictRetry}, nil
	}

	// The conflict check read the file already.
	if upToDate {
		return reconcile.Result{}, nil
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

	return reconcile.Result{}, nil
}

// rejectProfile marks a profile which cannot be installed until it, one of
// its base profiles or the SPOD configuration changes. Each of them triggers
// a reconcile, so it is not retried. An earlier version of the profile may be
// installed already, for example before the allow list got tightened or an
// OCI base profile changed. Its file gets removed, so that new pods cannot
// use a profile which is not allowed anymore.
func (r *Reconciler) rejectProfile(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	nodeStatus *nodestatus.StatusClient,
	reason string,
	rejectErr error,
	l logr.Logger,
) error {
	l.Error(rejectErr, "Not installing profile")
	r.reportError(sp, reason, util.EventActionInstall, rejectErr)

	if err := r.handleDeletion(ctx, sp, l); err != nil {
		l.Error(err, "Cannot remove rejected profile")
		r.reportError(sp, reasonCannotRemoveProfile, util.EventActionRemove, err)

		return fmt.Errorf("removing rejected profile: %w", err)
	}

	if err := nodeStatus.SetNodeStatus(ctx, secprofnodestatusapi.ProfileStateError); err != nil {
		r.reportError(sp, common.ReasonCannotUpdateStatus, util.EventActionUpdate, err)

		return fmt.Errorf("setting node status to error: %w", err)
	}

	return nil
}

// errorReporter returns the reporter of the errors of this controller.
func (r *Reconciler) errorReporter() common.ErrorReporter {
	return common.ErrorReporter{
		Record:   r.record,
		IncError: r.metrics.IncSeccompProfileError,
	}
}

// deletionReasons returns the event reasons for removing a profile.
func deletionReasons() common.DeletionReasons {
	return common.DeletionReasons{
		CannotUpdateProfile: reasonCannotUpdateProfile,
		CannotRemoveProfile: reasonCannotRemoveProfile,
		CannotUpdateStatus:  common.ReasonCannotUpdateStatus,
	}
}

// reconcileDisabled removes a disabled profile from the node, which may have
// installed it before it got disabled. This keeps the file if another profile
// owns it.
func (r *Reconciler) reconcileDisabled(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	return common.ReconcileDisabled(
		ctx, sp, nodeStatus, l, r.errorReporter(), deletionReasons(),
		func() error { return r.handleDeletion(ctx, sp, l) },
		nil,
	)
}

func (r *Reconciler) reconcileDeletion(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	nsc *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	return common.ReconcileDeletion(
		ctx,
		sp,
		nsc,
		r.client,
		l,
		r.record,
		deletionReasons(),
		r.metrics.IncSeccompProfileError,
		func() (reconcile.Result, error) { return reconcile.Result{}, r.handleDeletion(ctx, sp, l) },
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
// file on disk. It returns true if there is a conflict, and upToDate if it
// found the file to hold content already, so that it does not need to be read
// again.
func (r *Reconciler) handleFileConflict(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	nodeStatus *nodestatus.StatusClient,
	profilePath string,
	content []byte,
	l logr.Logger,
) (conflict, upToDate bool, err error) {
	// Usually there is no other profile with the same file, which the cache
	// shows without asking the API server on every reconcile. A profile
	// which is missing from the cache only matters if the file changes.
	_, cached, err := sibling(ctx, r.client, sp)
	if err != nil {
		return false, false, err
	}

	if !cached && !fileDiffers(profilePath, content) {
		return false, true, nil
	}

	owner, err := fileOwner(ctx, r.apiReader(), sp)
	if err != nil || owner == "" {
		return false, false, err
	}

	conflictErr := fmt.Errorf(
		"%w: %s is stored as %s like %s, rename one of them",
		errProfileFileConflict, sp.GetName(), sp.GetProfileFile(), owner,
	)
	l.Error(conflictErr, "Not saving profile")
	r.reportError(sp, reasonProfileFileConflict, util.EventActionInstall, conflictErr)

	if err := nodeStatus.SetNodeStatus(ctx, secprofnodestatusapi.ProfileStateError); err != nil {
		return true, false, fmt.Errorf("setting node status to error: %w", err)
	}

	return true, false, nil
}

func (r *Reconciler) handleDeletion(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	l logr.Logger,
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

	l.Info("removed profile", "path", profilePath)
	r.metrics.IncSeccompProfileDelete()

	return nil
}

func (r *Reconciler) validateProfile(
	ctx context.Context,
	profile *seccompprofileapi.SeccompProfile,
) error {
	spod, err := r.GetSPOD(ctx, r.client, r.namespace)
	if err != nil {
		return fmt.Errorf("retrieving the SPOD configuration: %w", err)
	}

	if len(spod.Spec.Security.AllowedSyscalls) > 0 {
		return seccompcheck.AllowProfile(
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
