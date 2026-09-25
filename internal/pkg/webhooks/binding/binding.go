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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

var ErrProfWithoutStatus = errors.New("profile hasn't been initialized with status")

const (
	// ephemeralContainersSubResource is the pod sub resource used to add
	// ephemeral containers to a running pod, for example by `kubectl debug`.
	ephemeralContainersSubResource = "ephemeralcontainers"

	// profileLookupTimeout bounds the time the retried profile lookups of a
	// single admission request may take, so that the webhook answers before
	// the API server gives up on it. The static webhook configuration uses a
	// timeout of five seconds, the operator managed one ten seconds.
	profileLookupTimeout = 3 * time.Second

	reasonProfileWithoutStatus = "ProfileWithoutStatus"
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

	server.Register(
		"/mutate-v1-pod-binding",
		&webhook.Admission{
			Handler: &podBinder{
				impl:              &defaultImpl{client: c, reader: reader},
				decoder:           admission.NewDecoder(scheme),
				log:               logf.Log.WithName("binding"),
				record:            utils.NewSafeRecorder(rec),
				operatorNamespace: operatorNamespace,
				isOpenShift:       isOpenShift,
			},
		},
	)
}

// containersByImage groups the provided containers by their image.
func containersByImage(ctrs []*corev1.Container) map[string][]*corev1.Container {
	res := make(map[string][]*corev1.Container, len(ctrs))
	for _, c := range ctrs {
		res[c.Image] = append(res[c.Image], c)
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
	existing := make(map[string]bool, len(oldPod.Spec.EphemeralContainers))
	for i := range oldPod.Spec.EphemeralContainers {
		existing[oldPod.Spec.EphemeralContainers[i].Name] = true
	}

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

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=core,resources=events,verbs=create
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch;update
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
	profileBindings, err := p.ListProfileBindings(ctx, client.InNamespace(req.Namespace))
	if err != nil {
		p.log.Error(err, "could not list profile bindings")

		return admission.Errored(http.StatusInternalServerError, err)
	}

	profilebindings := profileBindings.Items

	pod, admissionResponse := p.updatePod(ctx, profilebindings, &req)
	if !cmp.Equal(admissionResponse, admission.Response{}) {
		return admissionResponse
	}

	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		p.log.Error(err, "failed to encode pod")

		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
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

		return false
	}

	return selector.Matches(labels.Set(pod.GetLabels()))
}

// wildcardFunc applies the profile of a wildcard binding and returns whether
// the pod got changed. Containers in bound are already bound by an image
// specific binding of the same kind.
type wildcardFunc func(pod *corev1.Pod, bindProfile any, bound map[*corev1.Container]bool) bool

func (p *podBinder) updatePod(
	ctx context.Context,
	profilebindings []profilebindingapi.ProfileBinding,
	req *admission.Request,
) (*corev1.Pod, admission.Response) {
	isEphemeral := req.Operation == admissionv1.Update &&
		req.SubResource == ephemeralContainersSubResource

	// Pod security context fields are immutable after creation, so only
	// mutate on CREATE and when ephemeral containers get added. Other updates
	// would produce a patch the API server rejects.
	if !isEphemeral && (req.Operation != admissionv1.Create || req.SubResource != "") {
		return nil, admission.Allowed("pod update, skipping mutation")
	}

	pod := &corev1.Pod{}
	if err := p.decoder.Decode(*req, pod); err != nil {
		p.log.Error(err, "failed to decode pod")

		return nil, admission.Errored(http.StatusBadRequest, err)
	}

	var (
		ctrs          []*corev1.Container
		applyWildcard wildcardFunc
	)

	if isEphemeral {
		oldPod := &corev1.Pod{}
		if err := p.decoder.DecodeRaw(req.OldObject, oldPod); err != nil {
			p.log.Error(err, "failed to decode old pod")

			return nil, admission.Errored(http.StatusBadRequest, err)
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

	images := containersByImage(ctrs)

	// Wildcard bindings apply per profile kind, so a SeccompProfile and a
	// SelinuxProfile wildcard binding can both be enforced on the same pod.
	wildcardProfiles := map[profilebindingapi.ProfileBindingKind]any{}

	// Containers already bound by an image specific binding per profile kind.
	// Wildcard bindings act as a default and must not override them.
	boundContainers := map[profilebindingapi.ProfileBindingKind]map[*corev1.Container]bool{}

	podChanged := false

	for i := range profilebindings {
		pb := &profilebindings[i]
		profileKind := pb.Spec.ProfileRef.Kind

		// Skip bindings whose podSelector does not match the pod's labels.
		if !p.podMatchesSelector(pod, pb) {
			continue
		}

		bindProfile, skip, err := p.getProfile(ctx, lookup, pb, req.Namespace)
		if err != nil {
			return pod, admission.Errored(http.StatusInternalServerError, err)
		}

		if skip {
			continue
		}

		if pb.Spec.Image == profilebindingapi.SelectAllContainersImage {
			wildcardProfiles[profileKind] = bindProfile

			continue
		}

		if boundContainers[profileKind] == nil {
			boundContainers[profileKind] = map[*corev1.Container]bool{}
		}

		for _, c := range images[pb.Spec.Image] {
			boundContainers[profileKind][c] = true

			if p.addSecurityContext(c, bindProfile) {
				podChanged = true
			}
		}
	}

	for kind, bindProfile := range wildcardProfiles {
		if applyWildcard(pod, bindProfile, boundContainers[kind]) {
			podChanged = true
		}
	}

	if !podChanged {
		return pod, admission.Allowed("pod unchanged")
	}

	return pod, admission.Response{}
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
	namespace string,
) (bindProfile any, skip bool, err error) {
	profileKind := pb.Spec.ProfileRef.Kind
	key := types.NamespacedName{Namespace: namespace, Name: pb.Spec.ProfileRef.Name}

	enabled, err := p.cachedProfileKindEnabled(ctx, lookup, profileKind)
	if err != nil {
		p.log.Error(err, "failed to check if the profile kind is enabled", "kind", profileKind)

		return nil, false, err
	}

	// Profiles of enabled kinds may have been created just before the pod,
	// so wait for them to get installed. Disabled kinds do not change.
	lookupCtx := ctx

	if enabled {
		var cancel context.CancelFunc

		lookupCtx, cancel = context.WithDeadline(ctx, lookup.retryDeadline)
		defer cancel()
	}

	switch profileKind {
	case profilebindingapi.ProfileBindingKindSeccompProfile:
		bindProfile, err = p.getSeccompProfile(lookupCtx, key, enabled)
	case profilebindingapi.ProfileBindingKindSelinuxProfile:
		bindProfile, err = p.getSelinuxProfile(lookupCtx, key, enabled)
	case profilebindingapi.ProfileBindingKindAppArmorProfile:
		bindProfile, err = p.getAppArmorProfile(lookupCtx, key, enabled)
	default:
		p.log.Info("profile kind not supported", "kind", profileKind)

		return nil, true, nil
	}

	switch {
	case err == nil:
		return bindProfile, false, nil

	case kerrors.IsNotFound(err):
		// Rejecting the pod would block all pod operations in a namespace with
		// binding enabled, which might also lead to a DoS by a ProfileBinding
		// with a non-existing profileRef.
		p.log.Info("skip binding due to unavailable profile", "kind", profileKind, "profile", key)

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
	pod *corev1.Pod, bindProfile any, bound map[*corev1.Container]bool,
) bool {
	podChanged := p.addPodSecurityContext(pod, bindProfile)

	for _, c := range podContainers(pod) {
		if bound[c] || !hasContainerContext(c, bindProfile) {
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
	return func(_ *corev1.Pod, bindProfile any, bound map[*corev1.Container]bool) bool {
		podChanged := false

		for _, c := range ctrs {
			if bound[c] {
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

func (p *podBinder) getSeccompProfile(
	ctx context.Context,
	key types.NamespacedName,
	retry bool,
) (seccompProfile *seccompprofileapi.SeccompProfile, err error) {
	err = retryProfileLookup(ctx, retry, func() (retryErr error) {
		seccompProfile, retryErr = p.GetSeccompProfile(ctx, key)
		if retryErr != nil {
			return fmt.Errorf("getting profile: %w", retryErr)
		}

		if seccompProfile.Status.Status == "" {
			return fmt.Errorf("getting profile: %w", ErrProfWithoutStatus)
		}

		return nil
	})

	return seccompProfile, err
}

func (p *podBinder) getSelinuxProfile(
	ctx context.Context,
	key types.NamespacedName,
	retry bool,
) (selinuxProfile *selinuxprofileapi.SelinuxProfile, err error) {
	err = retryProfileLookup(ctx, retry, func() (retryErr error) {
		selinuxProfile, retryErr = p.GetSelinuxProfile(ctx, key)
		if retryErr != nil {
			return fmt.Errorf("getting profile: %w", retryErr)
		}

		if selinuxProfile.Status.Status == "" {
			return fmt.Errorf("getting profile: %w", ErrProfWithoutStatus)
		}

		return nil
	})

	return selinuxProfile, err
}

func (p *podBinder) getAppArmorProfile(
	ctx context.Context,
	key types.NamespacedName,
	retry bool,
) (appArmorProfile *apparmorprofileapi.AppArmorProfile, err error) {
	err = retryProfileLookup(ctx, retry, func() (retryErr error) {
		appArmorProfile, retryErr = p.GetAppArmorProfile(ctx, key)
		if retryErr != nil {
			return fmt.Errorf("getting profile: %w", retryErr)
		}

		if appArmorProfile.Status.Status == "" {
			return fmt.Errorf("getting profile: %w", ErrProfWithoutStatus)
		}

		return nil
	})

	return appArmorProfile, err
}

func (p *podBinder) addSecurityContext(
	c *corev1.Container, bindProfile any,
) bool {
	var podChanged bool

	switch v := bindProfile.(type) {
	case *seccompprofileapi.SeccompProfile:
		podChanged = p.addSeccompContext(c, v)
	case *selinuxprofileapi.SelinuxProfile:
		podChanged = p.addSelinuxContext(c, v)
	case *apparmorprofileapi.AppArmorProfile:
		podChanged = p.addAppArmorContext(c, v)
	default:
		p.log.Info("Unexpected Profile Type")

		return false
	}

	return podChanged
}

func (p *podBinder) addSeccompContext(
	c *corev1.Container, seccompProfile *seccompprofileapi.SeccompProfile,
) bool {
	profileRef := seccompProfile.Status.LocalhostProfile
	sp := corev1.SeccompProfile{
		Type:             corev1.SeccompProfileTypeLocalhost,
		LocalhostProfile: &profileRef,
	}

	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}

	if c.SecurityContext.SeccompProfile == nil {
		c.SecurityContext.SeccompProfile = &sp

		return true
	}

	// Make sure that the bound profile is really in the pod security context if already a profile
	// exists, otherwise it can be easily overwritten with something less permissive like
	// "type": "Unconfined", even though a specific profile is enforced through a binding.
	if !equality.Semantic.DeepEqual(c.SecurityContext.SeccompProfile, &sp) {
		c.SecurityContext.SeccompProfile = &sp

		return true
	}

	return false
}

func (p *podBinder) addSelinuxContext(
	c *corev1.Container, selinuxProfile *selinuxprofileapi.SelinuxProfile,
) bool {
	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}

	// Make sure that the bound profile is really in the container security context if the profile exists,
	// otherwise it can be easily overwritten with something less permissive, even though a specific
	// profile is enforced through a binding.
	return setSelinuxType(&c.SecurityContext.SELinuxOptions, selinuxProfile.Status.Usage)
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

func (p *podBinder) addAppArmorContext(
	c *corev1.Container, appArmorProfile *apparmorprofileapi.AppArmorProfile,
) bool {
	profileName := appArmorProfile.GetProfileName()
	aa := corev1.AppArmorProfile{
		Type:             corev1.AppArmorProfileTypeLocalhost,
		LocalhostProfile: &profileName,
	}

	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}

	if c.SecurityContext.AppArmorProfile == nil {
		c.SecurityContext.AppArmorProfile = &aa

		return true
	}

	// Make sure that the bound profile is really in the pod security context, otherwise
	// it can be easily overwritten with something less permissive, even though a specific
	// profile is enforced through a binding.
	if !equality.Semantic.DeepEqual(c.SecurityContext.AppArmorProfile, &aa) {
		c.SecurityContext.AppArmorProfile = &aa

		return true
	}

	return false
}

func (p *podBinder) addPodSecurityContext(
	pod *corev1.Pod, bindProfile any,
) bool {
	var podChanged bool

	switch v := bindProfile.(type) {
	case *seccompprofileapi.SeccompProfile:
		podChanged = p.addPodSeccompContext(pod, v)
	case *selinuxprofileapi.SelinuxProfile:
		podChanged = p.addPodSelinuxContext(pod, v)
	case *apparmorprofileapi.AppArmorProfile:
		podChanged = p.addPodAppArmorContext(pod, v)
	default:
		p.log.Info("Unexpected Profile Type")

		return false
	}

	return podChanged
}

func (p *podBinder) addPodSeccompContext(
	pod *corev1.Pod, seccompProfile *seccompprofileapi.SeccompProfile,
) bool {
	profileRef := seccompProfile.Status.LocalhostProfile
	sp := corev1.SeccompProfile{
		Type:             corev1.SeccompProfileTypeLocalhost,
		LocalhostProfile: &profileRef,
	}

	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}

	// Overwrite any existing value, otherwise it can be replaced with
	// something less permissive, even though a profile is enforced through a
	// binding.
	if equality.Semantic.DeepEqual(pod.Spec.SecurityContext.SeccompProfile, &sp) {
		return false
	}

	pod.Spec.SecurityContext.SeccompProfile = &sp

	return true
}

func (p *podBinder) addPodSelinuxContext(
	pod *corev1.Pod, selinuxProfile *selinuxprofileapi.SelinuxProfile,
) bool {
	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}

	// Overwrite any existing value, otherwise it can be replaced with
	// something less permissive, even though a profile is enforced through a
	// binding.
	return setSelinuxType(&pod.Spec.SecurityContext.SELinuxOptions, selinuxProfile.Status.Usage)
}

func (p *podBinder) addPodAppArmorContext(
	pod *corev1.Pod, appArmorProfile *apparmorprofileapi.AppArmorProfile,
) bool {
	profileName := appArmorProfile.GetProfileName()
	aa := corev1.AppArmorProfile{
		Type:             corev1.AppArmorProfileTypeLocalhost,
		LocalhostProfile: &profileName,
	}

	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}

	// Overwrite any existing value, otherwise it can be replaced with
	// something less permissive, even though a profile is enforced through a
	// binding.
	if equality.Semantic.DeepEqual(pod.Spec.SecurityContext.AppArmorProfile, &aa) {
		return false
	}

	pod.Spec.SecurityContext.AppArmorProfile = &aa

	return true
}
