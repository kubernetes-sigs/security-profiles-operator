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

package binding

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

var (
	ErrProfWithoutStatus = errors.New("profile hasn't been initialized with status")

	// errUnsupportedKind is returned for a binding of an unknown kind.
	errUnsupportedKind = errors.New("unsupported profile kind")
)

const (
	// profileLookupTimeout bounds the time the retried profile lookups of a
	// single admission request may take, so that the webhook answers before
	// the API server gives up on it. The webhook configurations use a
	// timeout of ten seconds.
	profileLookupTimeout = 3 * time.Second

	// missingProfileRetry is how long a profile which was not found after
	// waiting for it is only waited for missingProfileWait, instead of the
	// whole profileLookupTimeout with every pod.
	missingProfileRetry = time.Minute

	// missingProfileWait is how long a recently missing profile is waited for,
	// which covers the cache of the webhook catching up with a profile
	// created right before the pod.
	missingProfileWait = time.Second

	// maxMissingProfiles bounds the remembered missing profiles.
	maxMissingProfiles = 1000

	reasonProfileWithoutStatus = "ProfileWithoutStatus"
	reasonProfileNotFound      = "ProfileNotFound"
	reasonBindingConflict      = "ProfileBindingConflict"
	reasonInvalidPodSelector   = "InvalidPodSelector"
	reasonRecordedElsewhere    = "ProfileRecordedInOtherNamespace"
)

type podBinder struct {
	impl
	decoder admission.Decoder
	log     logr.Logger
	record  *utils.SafeRecorder

	// operatorNamespace is the namespace of the SPOD configuration.
	operatorNamespace string

	// isOpenShift is true on OpenShift, where SELinux is enabled by default.
	isOpenShift bool

	// missing holds the profiles which were not found after waiting for
	// them. A pointer, as a dry run works on a copy of the binder.
	missing *missingProfiles

	// dryRun is set for a dry run request, which must not change missing.
	dryRun bool
}

// missingProfiles holds the kind and name of the profiles which were not
// found after waiting for them, for missingProfileRetry. A nil one remembers
// nothing.
type missingProfiles struct {
	profiles *ttlcache.Cache[string, struct{}]
}

func newMissingProfiles() *missingProfiles {
	return &missingProfiles{profiles: ttlcache.New(
		ttlcache.WithTTL[string, struct{}](missingProfileRetry),
		ttlcache.WithCapacity[string, struct{}](maxMissingProfiles),
		ttlcache.WithDisableTouchOnHit[string, struct{}](),
	)}
}

// missingProfileKey is the key of a profile in missingProfiles.
func missingProfileKey(kind profilebindingapi.ProfileBindingKind, name string) string {
	return string(kind) + "/" + name
}

// recently reports whether the profile was found missing within
// missingProfileRetry.
func (m *missingProfiles) recently(key string) bool {
	return m != nil && m.profiles.Get(key) != nil
}

func (m *missingProfiles) add(key string) {
	if m != nil {
		m.profiles.Set(key, struct{}{}, ttlcache.DefaultTTL)
	}
}

func (m *missingProfiles) remove(key string) {
	if m != nil {
		m.profiles.Delete(key)
	}
}

// RegisterWebhook registers the binding webhook. The reader is used to read
// the SPOD configuration, which is not cached.
func RegisterWebhook(
	server webhook.Server,
	scheme *runtime.Scheme,
	rec util.EventRecorder,
	c client.Client,
	reader client.Reader,
	isOpenShift bool,
) {
	operatorNamespace, err := config.TryToGetOperatorNamespace()
	if err != nil {
		operatorNamespace = config.OperatorName
	}

	decoder := admission.NewDecoder(scheme)
	binder := &podBinder{
		impl:              &defaultImpl{client: c, reader: reader},
		decoder:           decoder,
		log:               logf.Log.WithName("binding"),
		record:            utils.NewSafeRecorder(rec),
		operatorNamespace: operatorNamespace,
		isOpenShift:       isOpenShift,
		missing:           newMissingProfiles(),
	}

	server.Register("/mutate-v1-pod-binding", &webhook.Admission{Handler: binder})

	server.Register(
		"/validate-v1-pod-binding-image",
		&webhook.Admission{
			Handler: &imageUpdateValidator{
				binder:  binder,
				decoder: decoder,
				log:     logf.Log.WithName("binding-image-update"),
			},
		},
	)
}

// containersByImage groups the provided containers by their normalized image.
func containersByImage(ctrs []*corev1.Container) map[string][]*corev1.Container {
	res := make(map[string][]*corev1.Container, len(ctrs))
	for _, c := range ctrs {
		image := util.NormalizeImage(c.Image)
		res[image] = append(res[image], c)
	}

	return res
}

// podContainers returns the init and regular containers of the pod.
func podContainers(pod *corev1.Pod) []*corev1.Container {
	ctrs := make([]*corev1.Container, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	for i := range pod.Spec.InitContainers {
		ctrs = append(ctrs, &pod.Spec.InitContainers[i])
	}

	for i := range pod.Spec.Containers {
		ctrs = append(ctrs, &pod.Spec.Containers[i])
	}

	return ctrs
}

// newEphemeralContainers returns the ephemeral containers of the pod which do
// not exist in the old pod. Existing ephemeral containers cannot be changed.
func newEphemeralContainers(pod, oldPod *corev1.Pod) []*corev1.Container {
	existing := utils.ExistingEphemeralContainers(pod, oldPod)

	var ctrs []*corev1.Container

	for i := range pod.Spec.EphemeralContainers {
		ec := &pod.Spec.EphemeralContainers[i]
		if existing[ec.Name] {
			continue
		}

		// The common fields of ephemeral containers are identical to the ones
		// of regular containers.
		ctrs = append(ctrs, (*corev1.Container)(&ec.EphemeralContainerCommon))
	}

	return ctrs
}

// Security Profiles Operator Webhook RBAC permissions
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles,verbs=get;list;watch

// Needed to skip bindings to profiles of disabled kinds:
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,namespace=security-profiles-operator,resources=securityprofilesoperatordaemons,verbs=get

// The event recorders use the events.k8s.io API, which creates an event and
// patches it for repeated ones:
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace=security-profiles-operator,resources=leases,verbs=create
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace=security-profiles-operator,resourceNames=security-profiles-operator-webhook-lock,resources=leases,verbs=get;patch;update

// Needed to authenticate and authorize metrics requests:
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

// OpenShift (This is ignored in other distros):
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security.openshift.io,namespace=security-profiles-operator,resourceNames=restricted-v2,resources=securitycontextconstraints,verbs=use

// OpenShift cluster TLS profile detection and watch (ignored in other distros):
// +kubebuilder:rbac:groups=config.openshift.io,resources=clusteroperators,verbs=get
// +kubebuilder:rbac:groups=config.openshift.io,resources=apiservers,verbs=get;list;watch

//nolint:gocritic // hugeParam: admission.Handler defines the signature
func (p *podBinder) Handle(ctx context.Context, req admission.Request) admission.Response {
	if rec := utils.RecorderForRequest(&req, p.record); rec != p.record {
		dryRun := *p
		dryRun.record = rec
		dryRun.dryRun = true
		p = &dryRun
	}

	profileBindings, err := p.ListProfileBindings(ctx, client.InNamespace(req.Namespace))
	if err != nil {
		p.log.Error(err, "could not list profile bindings")

		return admission.Errored(http.StatusInternalServerError, err)
	}

	profilebindings := profileBindings.Items

	pod, warnings, admissionResponse := p.updatePod(ctx, profilebindings, &req)
	if admissionResponse != nil {
		return admissionResponse.WithWarnings(warnings...)
	}

	// The patch only touches the mutated fields, so that the fields of the
	// pod which the vendored pod type does not know are kept.
	return utils.PodPatchResponse(p.decoder, &req, pod).WithWarnings(warnings...)
}

// sortBindings returns the bindings sorted by creation time and name, so that
// conflicting bindings get resolved the same way on every admission: the
// oldest binding wins.
func sortBindings(bindings []profilebindingapi.ProfileBinding) []*profilebindingapi.ProfileBinding {
	res := make([]*profilebindingapi.ProfileBinding, 0, len(bindings))
	for i := range bindings {
		res = append(res, &bindings[i])
	}

	slices.SortStableFunc(res, func(a, b *profilebindingapi.ProfileBinding) int {
		if c := a.CreationTimestamp.Compare(b.CreationTimestamp.Time); c != 0 {
			return c
		}

		return cmp.Compare(a.Name, b.Name)
	})

	return res
}

// conflict records that the binding was not applied, because an older binding
// of the same profile kind already binds a different profile, and returns a
// warning for the admission response. An empty container means the pod level.
func (p *podBinder) conflict(
	pb, winner *profilebindingapi.ProfileBinding, podName, container string,
) string {
	target := "pod " + podName
	if container != "" {
		target = fmt.Sprintf("container %s of pod %s", container, podName)
	}

	msg := fmt.Sprintf(
		"profile binding %s was not applied to %s, because the older binding %s already binds %s %s",
		pb.Name,
		target,
		winner.Name,
		winner.Spec.ProfileRef.Kind,
		winner.Spec.ProfileRef.Name,
	)

	p.log.Info(msg)
	p.record.Eventf(
		pb, nil, corev1.EventTypeWarning, reasonBindingConflict, util.EventActionMutate, "%s", msg,
	)

	return msg
}

// setAppliedBindings sets the annotation listing the bindings applied to the
// pod, which the binding tracker uses to only track pods using a binding. A
// value set by the pod author gets replaced. It returns true if the pod
// changed.
func setAppliedBindings(pod *corev1.Pod, applied sets.Set[string]) bool {
	existing, exists := pod.Annotations[profilebindingapi.AppliedBindingsAnnotation]

	if applied.Len() == 0 {
		if !exists {
			return false
		}

		delete(pod.Annotations, profilebindingapi.AppliedBindingsAnnotation)

		return true
	}

	value := strings.Join(sets.List(applied), ",")
	if exists && existing == value {
		return false
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}

	pod.Annotations[profilebindingapi.AppliedBindingsAnnotation] = value

	return true
}

// podMatchesSelector reports whether the binding's podSelector matches the
// pod's labels. A nil selector matches every pod, an invalid selector is treated
// as non-matching so the binding is skipped rather than blocking pod admission.
func (p *podBinder) podMatchesSelector(
	pod *corev1.Pod, pb *profilebindingapi.ProfileBinding,
) bool {
	if pb.Spec.PodSelector == nil {
		return true
	}

	selector, err := metav1.LabelSelectorAsSelector(pb.Spec.PodSelector)
	if err != nil {
		p.log.Error(err, "invalid podSelector, skipping binding", "binding", pb.Name)
		p.record.Eventf(
			pb,
			nil,
			corev1.EventTypeWarning,
			reasonInvalidPodSelector,
			util.EventActionMutate,
			"The binding was skipped for a pod, because its podSelector is invalid: %v",
			err,
		)

		return false
	}

	return selector.Matches(labels.Set(pod.GetLabels()))
}

// wildcardFunc applies the profile of a wildcard binding and returns whether
// the pod got changed. Containers in bound are already bound by an image
// specific binding of the same kind.
type wildcardFunc func(
	pod *corev1.Pod, bindProfile any, bound map[*corev1.Container]*profilebindingapi.ProfileBinding,
) bool

// updatePod applies the bindings to the pod. It returns the mutated pod, the
// warnings for the admission response and, unless the pod has to be patched,
// the admission response.
func (p *podBinder) updatePod(
	ctx context.Context,
	profilebindings []profilebindingapi.ProfileBinding,
	req *admission.Request,
) (*corev1.Pod, []string, *admission.Response) {
	isEphemeral := req.Operation == admissionv1.Update &&
		req.SubResource == utils.EphemeralContainersSubResource

	// Pod security context fields are immutable after creation, so only
	// mutate on CREATE and when ephemeral containers get added. Other updates
	// would produce a patch the API server rejects.
	if !isEphemeral && (req.Operation != admissionv1.Create || req.SubResource != "") {
		return nil, nil, new(admission.Allowed("pod update, skipping mutation"))
	}

	// The webhook fails closed, so binding Windows pods would reject every
	// Windows pod in the namespace.
	pod, podName, resp := utils.DecodePod(p.decoder, req, p.log)
	if resp != nil {
		return nil, nil, resp
	}

	var (
		ctrs          []*corev1.Container
		applyWildcard wildcardFunc
	)

	if isEphemeral {
		oldPod := &corev1.Pod{}
		if err := p.decoder.DecodeRaw(req.OldObject, oldPod); err != nil {
			p.log.Error(err, "failed to decode old pod")

			return nil, nil, new(admission.Errored(http.StatusBadRequest, err))
		}

		ctrs = newEphemeralContainers(pod, oldPod)
		applyWildcard = p.applyWildcardProfileToContainers(ctrs)
	} else {
		ctrs = podContainers(pod)
		applyWildcard = p.applyWildcardProfile
	}

	lookup := &profileLookup{
		retryDeadline: time.Now().Add(profileLookupTimeout),
		enabled:       map[profilebindingapi.ProfileBindingKind]bool{},
	}

	state := newBindState(podName, ctrs)

	for _, pb := range sortBindings(profilebindings) {
		// Skip bindings whose podSelector does not match the pod's labels.
		if !p.podMatchesSelector(pod, pb) {
			continue
		}

		bindProfile, skip, err := p.getProfile(ctx, lookup, pb)
		if errors.Is(err, ErrProfWithoutStatus) {
			return pod, state.warnings, new(admission.Denied(fmt.Sprintf(
				"profile binding %s binds %s %s, which is not installed yet: "+
					"retry once the profile has a status, the SecurityProfileNodeStatus "+
					"objects of the profile show its state per node",
				pb.Name, pb.Spec.ProfileRef.Kind, pb.Spec.ProfileRef.Name,
			)))
		}

		if err != nil {
			return pod, state.warnings, new(admission.Errored(http.StatusInternalServerError, err))
		}

		if skip {
			continue
		}

		p.applyBinding(state, pb, bindProfile)

		if namespace := recordingNamespace(bindProfile); namespace != "" &&
			namespace != req.Namespace {
			state.recordedElsewhere = append(
				state.recordedElsewhere, recordedProfile{binding: pb, namespace: namespace},
			)
		}
	}

	for kind, bindProfile := range state.wildcardProfiles {
		state.applied.Insert(state.wildcardBindings[kind].Name)

		if applyWildcard(pod, bindProfile, state.boundBy[kind]) {
			state.podChanged = true
		}
	}

	p.warnRecordedElsewhere(state, req.Namespace)

	// The ephemeralcontainers subresource only accepts changes to the
	// ephemeral containers, so the annotation is only set on creation.
	if !isEphemeral && setAppliedBindings(pod, state.applied) {
		state.podChanged = true
	}

	if !state.podChanged {
		return pod, state.warnings, new(admission.Allowed("pod unchanged"))
	}

	return pod, state.warnings, nil
}

// bindState is the state of applying the bindings to a pod.
type bindState struct {
	podName string

	// images are the containers to bind by their image.
	images map[string][]*corev1.Container

	// Wildcard bindings apply per profile kind, so a SeccompProfile and a
	// SelinuxProfile wildcard binding can both be enforced on the same pod.
	wildcardProfiles map[profilebindingapi.ProfileBindingKind]any
	wildcardBindings map[profilebindingapi.ProfileBindingKind]*profilebindingapi.ProfileBinding

	// boundBy is the image specific binding which bound a container per
	// profile kind. Wildcard bindings act as a default and must not override
	// them.
	boundBy map[profilebindingapi.ProfileBindingKind]map[*corev1.Container]*profilebindingapi.ProfileBinding

	// applied are the names of the applied bindings.
	applied sets.Set[string]

	// recordedElsewhere are the bindings to profiles which got recorded in
	// another namespace than the one of the pod.
	recordedElsewhere []recordedProfile

	warnings   []string
	podChanged bool
}

func newBindState(podName string, ctrs []*corev1.Container) *bindState {
	return &bindState{
		podName:          podName,
		images:           containersByImage(ctrs),
		wildcardProfiles: map[profilebindingapi.ProfileBindingKind]any{},
		wildcardBindings: map[profilebindingapi.ProfileBindingKind]*profilebindingapi.ProfileBinding{},
		boundBy:          map[profilebindingapi.ProfileBindingKind]map[*corev1.Container]*profilebindingapi.ProfileBinding{},
		applied:          sets.New[string](),
	}
}

// applyBinding applies an image specific binding to the containers and
// records a wildcard binding, which gets applied after all image specific
// ones. The bindings have to be passed in the order of sortBindings: of
// conflicting bindings of the same profile kind, the oldest one wins, so that
// a new binding cannot silently replace the profile enforced by an existing
// one.
func (p *podBinder) applyBinding(
	state *bindState, pb *profilebindingapi.ProfileBinding, bindProfile any,
) {
	profileKind := pb.Spec.ProfileRef.Kind

	if pb.Spec.Image == profilebindingapi.SelectAllContainersImage {
		if winner, ok := state.wildcardBindings[profileKind]; ok {
			if winner.Spec.ProfileRef.Name != pb.Spec.ProfileRef.Name {
				state.warnings = append(state.warnings, p.conflict(pb, winner, state.podName, ""))
			}

			return
		}

		state.wildcardBindings[profileKind] = pb
		state.wildcardProfiles[profileKind] = bindProfile

		return
	}

	if state.boundBy[profileKind] == nil {
		state.boundBy[profileKind] = map[*corev1.Container]*profilebindingapi.ProfileBinding{}
	}

	for _, c := range state.images[util.NormalizeImage(pb.Spec.Image)] {
		if winner, ok := state.boundBy[profileKind][c]; ok {
			if winner.Spec.ProfileRef.Name != pb.Spec.ProfileRef.Name {
				state.warnings = append(
					state.warnings, p.conflict(pb, winner, state.podName, c.Name),
				)
			}

			continue
		}

		state.boundBy[profileKind][c] = pb
		state.applied.Insert(pb.Name)

		if p.addSecurityContext(c, bindProfile) {
			state.podChanged = true
		}
	}
}

// recordedProfile is a binding to a profile recorded in another namespace.
type recordedProfile struct {
	binding   *profilebindingapi.ProfileBinding
	namespace string
}

// recordingNamespace returns the namespace of the recording which produced the
// profile, or an empty string if it was not recorded.
func recordingNamespace(bindProfile any) string {
	obj, ok := bindProfile.(metav1.Object)
	if !ok {
		return ""
	}

	return obj.GetLabels()[profilerecordingapi.ProfileToRecordingNamespaceLabel]
}

// warnRecordedElsewhere warns about the applied bindings to profiles recorded
// in another namespace than the one of the pod. The names of recorded profiles
// only consist of the recording and container name, so a recording in any
// namespace can produce the profile a binding expects. Sharing profiles across
// namespaces is valid, so the binding still gets applied.
func (p *podBinder) warnRecordedElsewhere(state *bindState, namespace string) {
	for _, r := range state.recordedElsewhere {
		if !state.applied.Has(r.binding.Name) {
			continue
		}

		msg := fmt.Sprintf(
			"profile binding %s applied %s %s to pod %s, which was recorded in namespace %s "+
				"instead of %s: verify that it is the intended profile",
			r.binding.Name,
			r.binding.Spec.ProfileRef.Kind,
			r.binding.Spec.ProfileRef.Name,
			state.podName,
			r.namespace,
			namespace,
		)

		p.log.Info(msg)
		p.record.Eventf(
			r.binding, nil, corev1.EventTypeWarning, reasonRecordedElsewhere,
			util.EventActionMutate, "%s", msg,
		)

		state.warnings = append(state.warnings, msg)
	}
}

// profileLookup holds the state of the profile lookups of an admission
// request.
type profileLookup struct {
	// retryDeadline bounds the retries of all lookups.
	retryDeadline time.Time

	// enabled caches whether the profile kinds are enabled in the SPOD.
	enabled map[profilebindingapi.ProfileBindingKind]bool
}

// getProfile returns the profile referenced by the binding, or whether the
// binding has to be skipped. Bindings to profiles which do not exist are
// skipped, because rejecting the pod would block every pod matching the
// binding. Profiles without status are not installed yet, so pods get
// rejected, unless the SPOD does not enable the profile kind, which means
// that no daemon ever reports a status.
func (p *podBinder) getProfile(
	ctx context.Context,
	lookup *profileLookup,
	pb *profilebindingapi.ProfileBinding,
) (bindProfile any, skip bool, err error) {
	profileKind := pb.Spec.ProfileRef.Kind
	// Profiles are cluster scoped, so the key carries no namespace.
	key := types.NamespacedName{Name: pb.Spec.ProfileRef.Name}

	enabled, err := p.cachedProfileKindEnabled(ctx, lookup, profileKind)
	if err != nil {
		p.log.Error(err, "failed to check if the profile kind is enabled", "kind", profileKind)

		return nil, false, err
	}

	lookupKind := func(retry bool, deadline time.Time) (any, error) {
		lookupCtx := ctx

		if retry {
			var cancel context.CancelFunc

			lookupCtx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}

		switch profileKind {
		case profilebindingapi.ProfileBindingKindSeccompProfile:
			return lookupProfile(lookupCtx, key, retry, p.GetSeccompProfile)
		case profilebindingapi.ProfileBindingKindSelinuxProfile:
			return lookupProfile(lookupCtx, key, retry, p.GetSelinuxProfile)
		case profilebindingapi.ProfileBindingKindAppArmorProfile:
			return lookupProfile(lookupCtx, key, retry, p.GetAppArmorProfile)
		default:
			return nil, errUnsupportedKind
		}
	}

	// Profiles of enabled kinds may have been created just before the pod,
	// so wait for them to get installed. Disabled kinds do not change. A
	// profile which was missing after waiting is likely to stay missing, so
	// the pods which follow wait for it shortly for a while, and wait for its
	// status as long as before once it exists.
	missingKey := missingProfileKey(profileKind, key.Name)
	recentlyMissing := p.missing.recently(missingKey)

	deadline := lookup.retryDeadline
	if shortDeadline := time.Now().Add(missingProfileWait); recentlyMissing &&
		shortDeadline.Before(deadline) {
		deadline = shortDeadline
	}

	bindProfile, err = lookupKind(enabled, deadline)
	if enabled && recentlyMissing && err != nil && !kerrors.IsNotFound(err) {
		bindProfile, err = lookupKind(true, lookup.retryDeadline)
	}

	if errors.Is(err, errUnsupportedKind) {
		p.log.Info("profile kind not supported", "kind", profileKind)

		return nil, true, nil
	}

	if !kerrors.IsNotFound(err) && !p.dryRun {
		p.missing.remove(missingKey)
	}

	switch {
	case err == nil:
		return bindProfile, false, nil

	case kerrors.IsNotFound(err):
		// Rejecting the pod would block all pod operations in a namespace with
		// binding enabled, which might also lead to a DoS by a ProfileBinding
		// with a non-existing profileRef.
		p.log.Info("skip binding due to unavailable profile", "kind", profileKind, "profile", key)

		// Reported once while it stays missing, not for every pod.
		if !recentlyMissing {
			if !p.dryRun {
				p.missing.add(missingKey)
			}

			p.record.Eventf(
				pb,
				nil,
				corev1.EventTypeWarning,
				reasonProfileNotFound,
				util.EventActionMutate,
				"%s %s does not exist, the binding was not applied to a pod",
				profileKind,
				key.Name,
			)
		}

		return nil, true, nil

	case errors.Is(err, ErrProfWithoutStatus) && enabled:
		// Admitting the pod before a daemon installed the profile would run
		// it without the enforced profile.
		p.log.Error(err, "profile has no status yet", "kind", profileKind, "profile", key)

		return nil, false, err

	case errors.Is(err, ErrProfWithoutStatus):
		// No daemon ever reports a status for a disabled kind, so rejecting
		// the pod would block it forever.
		p.log.Info(
			"skip binding due to profile of a disabled kind", "kind", profileKind, "profile", key,
		)
		p.record.Eventf(
			pb,
			nil,
			corev1.EventTypeWarning,
			reasonProfileWithoutStatus,
			util.EventActionMutate,
			"%s %s has no status because the kind is disabled, the binding was not applied to a pod",
			profileKind,
			key.Name,
		)

		return nil, true, nil

	default:
		p.log.Error(err, "failed to get profile", "kind", profileKind, "profile", key)

		return nil, false, err
	}
}

// cachedProfileKindEnabled is profileKindEnabled, which reads the SPOD only
// once per profile kind and admission request.
func (p *podBinder) cachedProfileKindEnabled(
	ctx context.Context, lookup *profileLookup, kind profilebindingapi.ProfileBindingKind,
) (bool, error) {
	if enabled, ok := lookup.enabled[kind]; ok {
		return enabled, nil
	}

	enabled, err := p.profileKindEnabled(ctx, kind)
	if err != nil {
		return false, err
	}

	lookup.enabled[kind] = enabled

	return enabled, nil
}

// profileKindEnabled returns true if the SPOD configuration enables the
// profile kind. A missing configuration counts as enabled, so that a binding
// never gets skipped by mistake.
func (p *podBinder) profileKindEnabled(
	ctx context.Context, kind profilebindingapi.ProfileBindingKind,
) (bool, error) {
	// Seccomp support cannot be disabled.
	if kind != profilebindingapi.ProfileBindingKindSelinuxProfile &&
		kind != profilebindingapi.ProfileBindingKindAppArmorProfile {
		return true, nil
	}

	spod, err := p.GetSPOD(ctx, types.NamespacedName{
		Name: config.SPOdName, Namespace: p.operatorNamespace,
	})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return true, nil
		}

		return false, err
	}

	if spod == nil {
		return true, nil
	}

	if kind == profilebindingapi.ProfileBindingKindSelinuxProfile {
		// SELinux is enabled by default on OpenShift.
		return ptr.Deref(spod.Spec.Selinux.Enable, p.isOpenShift), nil
	}

	return ptr.Deref(spod.Spec.EnableAppArmor, false), nil
}

// applyWildcardProfile sets the profile of a wildcard binding on the pod
// security context. Containers which set their own value of the same kind
// would take precedence over the pod level value, so they get overwritten as
// well, unless an image specific binding already bound them.
func (p *podBinder) applyWildcardProfile(
	pod *corev1.Pod,
	bindProfile any,
	bound map[*corev1.Container]*profilebindingapi.ProfileBinding,
) bool {
	podChanged := p.addPodSecurityContext(pod, bindProfile)

	for _, c := range podContainers(pod) {
		if _, ok := bound[c]; ok || !hasContainerContext(c, bindProfile) {
			continue
		}

		if p.addSecurityContext(c, bindProfile) {
			podChanged = true
		}
	}

	return podChanged
}

// applyWildcardProfileToContainers returns a wildcardFunc which sets the
// profile of a wildcard binding on the provided containers. It is used for
// ephemeral containers, because the pod security context cannot be changed
// when they get added, and the pod might have been created before the binding.
func (p *podBinder) applyWildcardProfileToContainers(ctrs []*corev1.Container) wildcardFunc {
	return func(
		_ *corev1.Pod,
		bindProfile any,
		bound map[*corev1.Container]*profilebindingapi.ProfileBinding,
	) bool {
		podChanged := false

		for _, c := range ctrs {
			if _, ok := bound[c]; ok {
				continue
			}

			if p.addSecurityContext(c, bindProfile) {
				podChanged = true
			}
		}

		return podChanged
	}
}

// hasContainerContext returns true if the container sets its own security
// context value for the kind of the provided profile.
func hasContainerContext(c *corev1.Container, bindProfile any) bool {
	if c.SecurityContext == nil {
		return false
	}

	switch bindProfile.(type) {
	case *seccompprofileapi.SeccompProfile:
		return c.SecurityContext.SeccompProfile != nil
	case *selinuxprofileapi.SelinuxProfile:
		return c.SecurityContext.SELinuxOptions != nil
	case *apparmorprofileapi.AppArmorProfile:
		return c.SecurityContext.AppArmorProfile != nil
	default:
		return false
	}
}

// retryProfileLookup runs get until it succeeds or fails with an error other
// than a missing profile or status, because the profile might have been
// created just before the pod. It stops early when ctx is done and returns the
// last error. Without retry, get runs only once.
func retryProfileLookup(ctx context.Context, retry bool, get func() error) error {
	backoff := util.DefaultBackoff()

	for {
		err := get()
		if err == nil || !retry ||
			(!errors.Is(err, ErrProfWithoutStatus) && !kerrors.IsNotFound(err)) ||
			backoff.Steps <= 1 {
			return err
		}

		timer := time.NewTimer(backoff.Step())

		select {
		case <-ctx.Done():
			timer.Stop()

			return err
		case <-timer.C:
		}
	}
}

// lookupProfile gets the profile of the key with get, retried as
// retryProfileLookup describes. A profile without status is not installed
// yet, which ErrProfWithoutStatus tells.
func lookupProfile[T profilebase.StatusBaseUser](
	ctx context.Context,
	key types.NamespacedName,
	retry bool,
	get func(context.Context, types.NamespacedName) (T, error),
) (profile T, err error) {
	err = retryProfileLookup(ctx, retry, func() error {
		var getErr error

		profile, getErr = get(ctx, key)
		if getErr != nil {
			return getErr
		}

		if profile.GetStatusBase().Status == "" {
			return ErrProfWithoutStatus
		}

		return nil
	})

	return profile, err
}

// addSecurityContext sets the profile on the container and returns whether
// the container changed.
func (p *podBinder) addSecurityContext(
	c *corev1.Container, bindProfile any,
) bool {
	if !p.supportedProfile(bindProfile) {
		return false
	}

	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}

	sc := c.SecurityContext

	return p.setProfile(&sc.SeccompProfile, &sc.SELinuxOptions, &sc.AppArmorProfile, bindProfile)
}

// addPodSecurityContext sets the profile on the pod security context and
// returns whether the pod changed.
func (p *podBinder) addPodSecurityContext(
	pod *corev1.Pod, bindProfile any,
) bool {
	if !p.supportedProfile(bindProfile) {
		return false
	}

	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}

	sc := pod.Spec.SecurityContext

	return p.setProfile(&sc.SeccompProfile, &sc.SELinuxOptions, &sc.AppArmorProfile, bindProfile)
}

// supportedProfile returns true if the profile is of a kind which bindings
// apply.
func (p *podBinder) supportedProfile(bindProfile any) bool {
	switch bindProfile.(type) {
	case *seccompprofileapi.SeccompProfile,
		*selinuxprofileapi.SelinuxProfile,
		*apparmorprofileapi.AppArmorProfile:
		return true
	default:
		p.log.Info("Unexpected Profile Type")

		return false
	}
}

// setProfile sets the field of a pod or container security context which
// belongs to the kind of the profile. Any existing value gets overwritten,
// otherwise it could be replaced with something less permissive, like
// "type": "Unconfined", even though a profile is enforced through a binding.
// It returns whether the field changed.
func (p *podBinder) setProfile(
	seccomp **corev1.SeccompProfile,
	selinux **corev1.SELinuxOptions,
	apparmor **corev1.AppArmorProfile,
	bindProfile any,
) bool {
	switch v := bindProfile.(type) {
	case *seccompprofileapi.SeccompProfile:
		return setIfDifferent(seccomp, &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: new(v.Status.LocalhostProfile),
		})
	case *selinuxprofileapi.SelinuxProfile:
		return setSelinuxType(selinux, v.Status.Usage)
	case *apparmorprofileapi.AppArmorProfile:
		return setIfDifferent(apparmor, &corev1.AppArmorProfile{
			Type:             corev1.AppArmorProfileTypeLocalhost,
			LocalhostProfile: new(v.GetProfileName()),
		})
	default:
		return false
	}
}

// setIfDifferent sets the field to the value unless it is equal already, and
// returns whether it changed.
func setIfDifferent[T any](field **T, value *T) bool {
	if equality.Semantic.DeepEqual(*field, value) {
		return false
	}

	*field = value

	return true
}

// setSelinuxType sets the SELinux type of the provided options. Other fields
// like the MCS level are kept, because they may be required by the cluster,
// for example set by the OpenShift SCC admission.
func setSelinuxType(opts **corev1.SELinuxOptions, usage string) bool {
	if *opts == nil {
		*opts = &corev1.SELinuxOptions{Type: usage}

		return true
	}

	if (*opts).Type == usage {
		return false
	}

	(*opts).Type = usage

	return true
}
