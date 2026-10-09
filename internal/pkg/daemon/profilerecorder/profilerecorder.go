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

package profilerecorder

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	bpfrecorderapi "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	enricherapi "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile/crd2armor"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/recordingmerger"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	reasonProfileRecording      string = "ProfileRecording"
	reasonProfileCreated        string = "ProfileCreated"
	reasonProfileCreationFailed string = "CannotCreateProfile"
	reasonProfileMergeFailed    string = "CannotMergeProfile"
	reasonAnnotationParsing     string = "AnnotationParsing"
	reasonRecordingIncomplete   string = "RecordingIncomplete"
	reasonRecordingAbandoned    string = "RecordingAbandoned"

	seContextRequiredParts = 3
)

// storeProfileBackoff retries conflicting writes of a recorded profile. The
// daemons of all nodes running a recorded workload merge into the same
// profile at once, so the retries spread out with jitter and the default of
// five quick attempts would leave some of them failed.
var storeProfileBackoff = wait.Backoff{
	Steps:    12,
	Duration: 10 * time.Millisecond,
	Factor:   1.5,
	Jitter:   1,
	Cap:      5 * time.Second,
}

var errNameNotValid = errors.New(
	"recording name is not valid DNS1123 subdomain, check profileRecording events")

var (
	errInvalidAnnotation = errors.New("invalid annotation")
	// errProfileRejected is returned when the API server rejects a recorded
	// profile for good, which retrying cannot change.
	errProfileRejected         = errors.New("recorded profile rejected")
	errRecordedProfileNotFound = errors.New("recorded profile not found")
	errRecordingGone           = errors.New("profile recording no longer exists")
	errMergeFailed             = errors.New("merge profile")
	// errRecorderDisabled is returned if the recorder of a pod got disabled
	// in the SPOD. The daemon restarts without it, which loses the recorded
	// data anyway.
	errRecorderDisabled = errors.New("not enabled")
	// errBpfRecorderUnavailable is returned if the BPF recorder cannot hand
	// out the recorded data at all, for example because it stopped a
	// recording which looked abandoned, or got restarted.
	errBpfRecorderUnavailable = errors.New("bpf recorder cannot provide the recorded data")
	// errIncompleteRead is returned if the BPF recorder cannot read all the
	// data recorded for a profile.
	errIncompleteRead = errors.New("bpf recorder cannot read all recorded data")
)

// unrecordable reports whether a collect error means the pod can never be
// collected, so that the reconciler releases it instead of requeuing forever.
func unrecordable(err error) bool {
	return errors.Is(err, errNameNotValid) ||
		errors.Is(err, errRecordingGone) ||
		errors.Is(err, errRecorderDisabled) ||
		errors.Is(err, errBpfRecorderUnavailable)
}

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &RecorderReconciler{
		impl:                      &defaultImpl{},
		forbiddenGracePeriod:      defaultForbiddenGracePeriod,
		incompleteReadGracePeriod: defaultIncompleteReadGracePeriod,
	}
}

type RecorderReconciler struct {
	impl
	client client.Client
	// uncachedClient reads what the daemon does not watch, like the
	// namespaces.
	uncachedClient client.Client
	log            logr.Logger
	record         util.EventRecorder
	nodeAddresses  []string
	// namespace is the namespace of the operator, which holds the SPOD.
	namespace   string
	podsToWatch sync.Map
	// rejectedPods maps the pods with ignored recording annotations to a
	// rejectedPod, so that every update of such a pod does not warn about
	// them again.
	rejectedPods sync.Map
	// scope caches whether the recording webhook applies to a pod.
	scope recordingScope
	// forbiddenAttempts holds per attemptKey the *failedAttempts of storing
	// a profile.
	forbiddenAttempts sync.Map
	// forbiddenGracePeriod is how long storing a profile is retried at least
	// while the API server forbids it.
	forbiddenGracePeriod time.Duration
	// incompleteReads holds per attemptKey the *failedAttempts of reading
	// the data the BPF recorder recorded for a profile.
	incompleteReads sync.Map
	// incompleteReadGracePeriod is how long reading the recorded data of a
	// profile is retried at least while the BPF recorder cannot read all of
	// it.
	incompleteReadGracePeriod time.Duration
}

// attemptKey identifies the attempts of a pod to collect or store a profile.
// Profiles of different namespaces can have the same name.
type attemptKey struct {
	pod     types.NamespacedName
	profile types.NamespacedName
}

type profileToCollect struct {
	kind profilerecordingapi.ProfileRecordingKind
	name string
}

type podToWatch struct {
	baseName types.NamespacedName
	// uid tells the pod apart from a pod created under the same name later.
	uid      types.UID
	recorder profilerecordingapi.ProfileRecorder
	profiles []profileToCollect
	// recordings holds the state of the recordings the profiles belong to,
	// keyed by recording name, as it was when the pod started being recorded.
	recordings map[string]recordingState
}

// recordingState holds what storing a recorded profile needs to know about
// its ProfileRecording. It is captured when a pod starts being recorded, so
// that the profiles of a pod which outlives its recording are still stored.
type recordingState struct {
	partial bool
	disable bool
}

func recordingStateOf(recording *profilerecordingapi.ProfileRecording) recordingState {
	return recordingState{
		partial: recording.Spec.MergeStrategy == profilerecordingapi.ProfileMergeContainers,
		disable: recording.Spec.DisableProfileAfterRecording,
	}
}

// Name returns the name of the controller.
func (r *RecorderReconciler) Name() string {
	return "recorder-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *RecorderReconciler) SchemeBuilder() runtime.SchemeBuilder {
	return profilerecordingapi.SchemeBuilder
}

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings,verbs=get;list;watch;update;patch

// Setup is the initialization of the controller.
func (r *RecorderReconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	const name = "profilerecorder"

	c, err := r.NewClient(mgr)
	if err != nil {
		return fmt.Errorf("cannot get client connection: %w", err)
	}

	node := &corev1.Node{}
	if err := r.ClientGet(
		ctx, c, client.ObjectKey{Name: os.Getenv(config.NodeNameEnvKey)}, node,
	); err != nil {
		return fmt.Errorf("cannot get node object: %w", err)
	}

	r.log = ctrl.Log.WithName(r.Name())
	nodeAddresses := []string{}

	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			r.log.Info("Setting up profile recorder", "Node", addr.Address)
			nodeAddresses = append(nodeAddresses, addr.Address)

			break
		}
	}

	if len(nodeAddresses) == 0 {
		return errors.New("unable to get node's internal Address")
	}

	namespace, err := r.OperatorNamespace()
	if err != nil {
		return fmt.Errorf("getting the operator namespace: %w", err)
	}

	r.client = r.ManagerGetClient(mgr)
	r.uncachedClient = c
	r.nodeAddresses = nodeAddresses
	r.namespace = namespace
	r.record = r.ManagerGetEventRecorder(mgr, name)

	return r.NewControllerManagedBy(
		mgr, name, r.isPodWithTraceAnnotation, r.isPodOnLocalNode, r,
	)
}

// getSPOD returns the SPOD. Like every call of the reconciler, it is bound
// by the timeout of the reconcile.
func (r *RecorderReconciler) getSPOD(
	ctx context.Context,
) (*spodapi.SecurityProfilesOperatorDaemon, error) {
	return r.GetSPOD(ctx, r.client, r.namespace)
}

// Healthz is the liveness probe endpoint of the controller.
func (r *RecorderReconciler) Healthz(*http.Request) error {
	if r.record == nil {
		return errors.New("recorder reconciler not initialized")
	}

	return nil
}

func (r *RecorderReconciler) isPodOnLocalNode(obj runtime.Object) bool {
	p, ok := obj.(*corev1.Pod)

	if !ok {
		return false
	}

	return slices.Contains(r.nodeAddresses, p.Status.HostIP)
}

func (r *RecorderReconciler) isPodWithTraceAnnotation(obj runtime.Object) bool {
	p, ok := obj.(*corev1.Pod)

	if !ok {
		return false
	}

	for key := range p.Annotations {
		if strings.HasPrefix(key, config.SelinuxProfileRecordLogsAnnotationKey) ||
			strings.HasPrefix(key, config.SeccompProfileRecordLogsAnnotationKey) ||
			strings.HasPrefix(key, config.SeccompProfileRecordBpfAnnotationKey) ||
			strings.HasPrefix(key, config.ApparmorProfileRecordBpfAnnotationKey) {
			return true
		}
	}

	return false
}

// shouldRecordContainer mirrors the webhook's container selection: an empty
// container list means every container of the pod is recorded.
func shouldRecordContainer(
	containerName string, recording *profilerecordingapi.ProfileRecording,
) bool {
	if recording.Spec.Containers == nil {
		return true
	}

	return slices.Contains(recording.Spec.Containers, containerName)
}

// rejectedPod holds the ignored recording annotations of a pod, which got
// reported already.
type rejectedPod struct {
	uid         types.UID
	annotations map[string]struct{}
}

// authorizedProfiles drops the profiles whose annotation is not backed by a
// ProfileRecording that selects this pod, and all of them if the recording
// webhook does not apply to the pod or its namespace.
//
// The trace annotations are written by the recording webhook, but that webhook
// is gated by a namespace selector, so in a namespace where it never runs the
// pod author controls them outright. Profiles are cluster scoped and the
// recorded profile is named after the annotation, so an unfiltered annotation
// lets any user who can create a pod drive this privileged daemon into
// creating or overwriting an arbitrarily named profile that other namespaces
// may rely on.
func (r *RecorderReconciler) authorizedProfiles(
	ctx context.Context,
	pod *corev1.Pod,
	profiles []profileToCollect,
	recorder profilerecordingapi.ProfileRecorder,
) ([]profileToCollect, map[string]recordingState, error) {
	if len(profiles) == 0 {
		return profiles, nil, nil
	}

	// An ignored annotation is reported once per pod, a newly ignored one of
	// the same pod gets reported as well.
	podKey := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}.String()
	warnedBefore := map[string]struct{}{}

	if value, ok := r.rejectedPods.Load(podKey); ok {
		if previous, ok := value.(rejectedPod); ok && previous.uid == pod.UID {
			warnedBefore = previous.annotations
		}
	}

	enabled, err := r.recordingEnabled(ctx, pod)
	if err == nil && !enabled && slices.ContainsFunc(profiles, func(p profileToCollect) bool {
		_, warned := warnedBefore[p.name]

		return !warned
	}) {
		// The cached scope may be older than the pod, like the labels of a
		// namespace which got labeled for recording right before the pod got
		// created. Nothing looks at a rejected pod again unless it changes,
		// so its first rejection is checked against the current scope.
		r.scope.forget(pod.Namespace)
		enabled, err = r.recordingEnabled(ctx, pod)
	}

	if err != nil {
		return nil, nil, err
	}

	var recordings *profilerecordingapi.ProfileRecordingList
	if enabled {
		recordings, err = r.ListRecordings(ctx, r.client, pod.Namespace)
		if err != nil {
			return nil, nil, fmt.Errorf("list profile recordings: %w", err)
		}
	}

	podLabels := k8slabels.Set(pod.GetLabels())
	authorized := make([]profileToCollect, 0, len(profiles))
	states := map[string]recordingState{}

	rejectedNow := map[string]struct{}{}
	defer func() {
		if len(rejectedNow) > 0 {
			r.rejectedPods.Store(podKey, rejectedPod{uid: pod.UID, annotations: rejectedNow})
		} else {
			r.rejectedPods.Delete(podKey)
		}
	}()

	reject := func(annotation string) (warned bool) {
		rejectedNow[annotation] = struct{}{}
		_, warned = warnedBefore[annotation]

		return warned
	}

	if !enabled {
		warned := true
		for _, profile := range profiles {
			warned = reject(profile.name) && warned
		}

		if !warned {
			r.log.Info(
				"Ignoring recording annotations, the recording webhook does not apply to the pod",
				"pod",
				pod.Name,
				"namespace",
				pod.Namespace,
			)
			r.record.Eventf(
				pod,
				nil,
				util.EventTypeWarning,
				reasonAnnotationParsing,
				util.EventActionRecord,
				"%s",
				"ignoring recording annotations, profile recording is not enabled for namespace "+
					pod.Namespace+" or the pod",
			)
		}

		return authorized, states, nil
	}

	for _, profile := range profiles {
		// The annotation value starts with the recording and container name.
		// The trailing nonce and timestamp are not predictable, and are not
		// security relevant because the recorded profile is named from the
		// first two fields.
		parsed, err := parseProfileAnnotation(profile.name)
		if err != nil {
			// Report it here and drop it. Passing it through would make the
			// caller see a non-empty profile list and arm the node's BPF
			// recorder, which is exactly what authorization must prevent, and
			// the downstream handling requeues such an annotation forever.
			if !reject(profile.name) {
				r.log.Info(
					"Ignoring malformed recording annotation",
					"pod", pod.Name, "namespace", pod.Namespace,
					"annotation", profile.name, "error", err.Error(),
				)
				r.record.Eventf(
					pod,
					nil,
					util.EventTypeWarning,
					reasonAnnotationParsing,
					util.EventActionRecord,
					"%s",
					"ignoring malformed recording annotation: "+err.Error(),
				)
			}

			continue
		}

		if recording := r.recordingAuthorizes(
			recordings, podLabels, parsed, profile.kind, recorder,
		); recording != nil {
			authorized = append(authorized, profile)
			states[recording.Name] = recordingStateOf(recording)

			continue
		}

		if reject(profile.name) {
			continue
		}

		r.log.Info(
			"Ignoring recording annotation with no matching profile recording",
			"pod", pod.Name, "namespace", pod.Namespace,
			"recording", parsed.profileName, "container", parsed.cntName,
		)
		r.record.Eventf(
			pod,
			nil,
			util.EventTypeWarning,
			reasonAnnotationParsing,
			util.EventActionRecord,
			"%s",
			"ignoring recording annotation with no matching profile recording: "+
				parsed.profileName,
		)
	}

	return authorized, states, nil
}

// recordingAuthorizes returns the recording which asks for exactly this
// profile: same name, same kind, same recorder, a selector that matches the
// pod and a container the recording covers. It returns nil if there is none.
func (r *RecorderReconciler) recordingAuthorizes(
	recordings *profilerecordingapi.ProfileRecordingList,
	podLabels k8slabels.Set,
	parsed *parsedAnnotation,
	kind profilerecordingapi.ProfileRecordingKind,
	recorder profilerecordingapi.ProfileRecorder,
) *profilerecordingapi.ProfileRecording {
	for i := range recordings.Items {
		recording := &recordings.Items[i]

		if recording.Name != parsed.profileName ||
			recording.Spec.Kind != kind ||
			recording.Spec.Recorder != recorder {
			continue
		}

		selector, err := metav1.LabelSelectorAsSelector(recording.Spec.PodSelector)
		if err != nil {
			r.log.Error(err, "Invalid pod selector on profile recording",
				"recording", recording.Name)

			continue
		}

		if !selector.Matches(podLabels) {
			continue
		}

		if !shouldRecordContainer(parsed.cntName, recording) {
			continue
		}

		return recording
	}

	return nil
}

// Reconcile reconciles a pod event for profile recording.
//
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
func (r *RecorderReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	logger := r.log.WithValues("pod", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	// Every talk to the BPF recorder within this reconcile shares one
	// connection.
	bpf := r.newBpfRecorderSession()
	defer bpf.Close()

	pod, err := r.GetPod(ctx, r.client, req.NamespacedName)
	if err != nil {
		if kerrors.IsNotFound(err) {
			r.rejectedPods.Delete(req.String())

			return reconcile.Result{}, r.collectPod(ctx, req.NamespacedName, bpf, "removed")
		}

		// Returning an error means we will be requeued implicitly.
		logger.Error(err, "Error reading pod")

		return reconcile.Result{}, fmt.Errorf("cannot get pod: %w", err)
	}

	// Pods are normally picked up while pending. A running pod which is not
	// tracked yet was missed, for example because the daemon restarted, and
	// is still recorded rather than never.
	if pod.Status.Phase == corev1.PodPending || pod.Status.Phase == corev1.PodRunning {
		if value, ok := r.podsToWatch.Load(req.String()); ok {
			if watched, ok := value.(podToWatch); !ok || watched.uid == pod.UID {
				// We're tracking this pod already
				return reconcile.Result{}, nil
			}

			// The pod got deleted and created again under the same name, like
			// the pods of a StatefulSet, with both events handled at once. The
			// profiles of the previous pod are collected like for a removed
			// pod before the new one is recorded.
			logger.Info("Pod got replaced, collecting the profiles of the previous one")

			if err := r.collectPod(ctx, req.NamespacedName, bpf, "replaced"); err != nil {
				return reconcile.Result{}, err
			}
		}

		profiles, recorder := r.podProfiles(logger, pod)
		if len(profiles) == 0 {
			return reconcile.Result{}, nil
		}

		// Authorize before anything with side effects: arming the node's BPF
		// recorder must not be reachable from a pod annotation alone.
		profiles, recordings, err := r.authorizedProfiles(ctx, pod, profiles, recorder)
		if err != nil {
			return reconcile.Result{}, err
		}

		if len(profiles) == 0 {
			logger.Info("No profile recording requests the annotations on this pod")

			return reconcile.Result{}, nil
		}

		if recorder == profilerecordingapi.ProfileRecorderBpf {
			if err := r.startBpfRecorder(ctx, bpf, pod.UID); err != nil {
				logger.Error(err, "unable to start bpf recorder")

				return reconcile.Result{}, err
			}
		}

		r.trackPod(logger, req, pod, recorder, profiles, recordings)
	}

	// A failed pod does not run anymore either, and it may stay around for a
	// long time, for example as a failed Job pod. What it did until it
	// failed gets recorded, like for a pod which gets deleted.
	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return reconcile.Result{}, r.collectPod(
			ctx, req.NamespacedName, bpf, strings.ToLower(string(pod.Status.Phase)),
		)
	}

	return reconcile.Result{}, nil
}

// podProfiles returns the profiles which the annotations of a pod ask to record
// and the recorder for them. It returns no profiles if there are none or if the
// annotations cannot be parsed.
func (r *RecorderReconciler) podProfiles(
	logger logr.Logger, pod *corev1.Pod,
) ([]profileToCollect, profilerecordingapi.ProfileRecorder) {
	logProfiles, err := parseLogAnnotations(pod.Annotations)
	if err != nil {
		r.ignoreAnnotations(logger, pod, "log", err)

		return nil, ""
	}

	bpfProfiles, err := parseBpfAnnotations(pod.Annotations)
	if err != nil {
		r.ignoreAnnotations(logger, pod, "bpf", err)

		return nil, ""
	}

	switch {
	case len(logProfiles) > 0:
		return logProfiles, profilerecordingapi.ProfileRecorderLogs
	case len(bpfProfiles) > 0:
		return bpfProfiles, profilerecordingapi.ProfileRecorderBpf
	default:
		logger.Info("No log or bpf annotations found on pod")

		return nil, ""
	}
}

// ignoreAnnotations reports annotations of a pod which cannot be parsed.
// Malformed annotations could be set by users directly, which is why they are
// ignored.
func (r *RecorderReconciler) ignoreAnnotations(
	logger logr.Logger, pod *corev1.Pod, recorder string, err error,
) {
	logger.Info("Ignoring because unable to parse "+recorder+" annotation", "error", err)
	r.record.Eventf(
		pod,
		nil,
		util.EventTypeWarning,
		reasonAnnotationParsing,
		util.EventActionRecord,
		"%s",
		err.Error(),
	)
}

// trackPod remembers a pod whose profiles get recorded, so that they are
// collected once it is gone.
func (r *RecorderReconciler) trackPod(
	logger logr.Logger,
	req reconcile.Request,
	pod *corev1.Pod,
	recorder profilerecordingapi.ProfileRecorder,
	profiles []profileToCollect,
	recordings map[string]recordingState,
) {
	for _, prf := range profiles {
		logger.Info(
			"Recording profile",
			"kind",
			prf.kind,
			"name",
			prf.name,
			"pod",
			req.String(),
		)
	}

	// for pods managed by a replicated controller, let's store the replicated
	// name so that we can later strip the suffix from the fully-generated pod name
	baseName := req.NamespacedName
	if pod.GenerateName != "" {
		baseName.Name = pod.GenerateName
	}

	r.podsToWatch.Store(
		req.String(),
		podToWatch{
			baseName:   baseName,
			uid:        pod.UID,
			recorder:   recorder,
			profiles:   profiles,
			recordings: recordings,
		},
	)
	r.record.Eventf(
		pod,
		nil,
		util.EventTypeNormal,
		reasonProfileRecording,
		util.EventActionRecord,
		"Recording profiles",
	)

	// The BPF recorder only sees what happens after it got armed, while
	// the log enricher records from the audit log regardless.
	if pod.Status.Phase == corev1.PodRunning &&
		recorder == profilerecordingapi.ProfileRecorderBpf {
		logger.Info("Started recording an already running pod, the profile may be incomplete")
		r.record.Eventf(
			pod,
			nil,
			util.EventTypeWarning,
			reasonRecordingIncomplete,
			util.EventActionRecord,
			"Recording started after the pod was already running, the profiles may be incomplete",
		)
	}
}

// collectPod collects the profiles of a pod which is gone, got replaced or
// does not run anymore. A pod whose profiles can never be collected is
// released, state describes the pod for the returned error.
func (r *RecorderReconciler) collectPod(
	ctx context.Context, podName types.NamespacedName, bpf *bpfRecorderSession, state string,
) error {
	collErr := r.collectProfile(ctx, podName, bpf)
	if unrecordable(collErr) {
		r.abandonPod(ctx, podName, collErr, bpf)

		return nil
	}

	if collErr != nil {
		return fmt.Errorf("collect profile for %s pod: %w", state, collErr)
	}

	return nil
}

func (r *RecorderReconciler) getBpfRecorderClient(
	ctx context.Context,
) (bpfrecorderapi.BpfRecorderClient, *grpc.ClientConn, error) {
	r.log.Info("Checking if bpf recorder is enabled")

	spod, err := r.getSPOD(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting SPOD config: %w", err)
	}

	enableBpfRecorderEnv, err := strconv.ParseBool(os.Getenv(config.EnableBpfRecorderEnvKey))
	if err != nil {
		enableBpfRecorderEnv = false
	}

	if !ptr.Deref(spod.Spec.Enricher.EnableBpfRecorder, false) && !enableBpfRecorderEnv {
		return nil, nil, fmt.Errorf("bpf recorder %w", errRecorderDisabled)
	}

	r.log.Info("Connecting to local GRPC bpf recorder server")

	conn, err := r.DialBpfRecorder()
	if err != nil {
		return nil, nil, fmt.Errorf("connect to bpf recorder GRPC server: %w", err)
	}

	bpfRecorderClient := bpfrecorderapi.NewBpfRecorderClient(conn)

	return bpfRecorderClient, conn, nil
}

// bpfRecorderSession connects to the BPF recorder at most once, so that a
// reconcile which talks to it several times reads the SPOD and dials only
// once. It is not safe for concurrent use.
type bpfRecorderSession struct {
	r      *RecorderReconciler
	client bpfrecorderapi.BpfRecorderClient
	conn   *grpc.ClientConn
	err    error
	done   bool
}

func (r *RecorderReconciler) newBpfRecorderSession() *bpfRecorderSession {
	return &bpfRecorderSession{r: r}
}

// Client returns the client of the BPF recorder, connecting on first use. A
// failed connection is not retried within the session.
func (s *bpfRecorderSession) Client(ctx context.Context) (bpfrecorderapi.BpfRecorderClient, error) {
	if !s.done {
		s.done = true
		s.client, s.conn, s.err = s.r.getBpfRecorderClient(ctx)
	}

	if s.err != nil {
		return nil, fmt.Errorf("get bpf recorder client: %w", s.err)
	}

	return s.client, nil
}

// Close closes the connection, if there is one.
func (s *bpfRecorderSession) Close() {
	if s.conn == nil {
		return
	}

	if err := s.conn.Close(); err != nil {
		s.r.log.Error(err, "Unable to close the bpf recorder connection")
	}

	s.conn = nil
}

// startBpfRecorder starts the BPF recorder for the pod with the UID. The
// recorder runs once per pod, so a retried start is not counted again.
func (r *RecorderReconciler) startBpfRecorder(
	ctx context.Context, bpf *bpfRecorderSession, uid types.UID,
) error {
	recorderClient, err := bpf.Client(ctx)
	if err != nil {
		return err
	}

	r.log.Info("Starting BPF recorder on node", "uid", uid)

	return r.StartBpfRecorder(ctx, recorderClient, bpfRecordingRequest(uid))
}

// bpfRecordingRequest returns the request which starts or stops the BPF
// recorder for the pod with the UID.
func bpfRecordingRequest(uid types.UID) *bpfrecorderapi.RecordingRequest {
	return &bpfrecorderapi.RecordingRequest{Id: string(uid)}
}

// abandonPod releases a pod whose profiles can never be collected and tells
// the user about it.
func (r *RecorderReconciler) abandonPod(
	ctx context.Context, podName types.NamespacedName, collErr error, bpf *bpfRecorderSession,
) {
	r.log.Error(collErr, "cannot collect profile", "pod", podName.String())

	// The pod may be gone already, which the event does not need.
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: podName.Name, Namespace: podName.Namespace,
	}}
	r.record.Eventf(
		pod,
		nil,
		util.EventTypeWarning,
		reasonRecordingAbandoned,
		util.EventActionRecord,
		"Giving up on collecting the recorded profiles: %s",
		collErr.Error(),
	)

	// Not reconcilable, so nothing will ever collect this pod: release it
	// rather than leaking the watch and the recorder.
	r.releaseUnrecordablePod(ctx, podName, bpf)
}

// releaseUnrecordablePod drops a pod whose profiles can never be collected. It
// must undo whatever Reconcile set up, otherwise the watch entry leaks, the
// recorded data stays in the recorders until they are full and, for the BPF
// recorder, the node stays armed for the lifetime of the daemon.
func (r *RecorderReconciler) releaseUnrecordablePod(
	ctx context.Context, podName types.NamespacedName, bpf *bpfRecorderSession,
) {
	// Nothing retries collecting or storing the profiles of the pod any more.
	for _, attempts := range []*sync.Map{&r.forbiddenAttempts, &r.incompleteReads} {
		attempts.Range(func(key, _ any) bool {
			if k, ok := key.(attemptKey); ok && k.pod == podName {
				attempts.Delete(key)
			}

			return true
		})
	}

	n := podName.String()

	value, ok := r.podsToWatch.Load(n)
	if !ok {
		return
	}

	if podToWatch, ok := value.(podToWatch); ok {
		switch podToWatch.recorder {
		case profilerecordingapi.ProfileRecorderBpf:
			r.releaseBpfProfiles(ctx, bpf, podToWatch.uid, podToWatch.profiles)
		case profilerecordingapi.ProfileRecorderLogs:
			r.releaseLogProfiles(ctx, podToWatch.profiles)
		}
	}

	r.podsToWatch.Delete(n)
}

// releaseBpfProfiles drops the data the BPF recorder holds for profiles and
// stops the recorder.
func (r *RecorderReconciler) releaseBpfProfiles(
	ctx context.Context, bpf *bpfRecorderSession, uid types.UID, profiles []profileToCollect,
) {
	recorderClient, err := bpf.Client(ctx)
	if err != nil {
		r.log.Error(err, "Unable to release bpf recorder for unrecordable pod")

		return
	}

	for _, prf := range profiles {
		if err := r.resetBpfProfile(ctx, recorderClient, prf); err != nil {
			r.log.Error(
				err,
				"Unable to reset recorded data for unrecordable pod",
				"profile",
				prf.name,
			)
		}
	}

	if err := r.StopBpfRecorder(ctx, recorderClient, bpfRecordingRequest(uid)); err != nil {
		r.log.Error(err, "Unable to stop bpf recorder for unrecordable pod")
	}
}

// dialEnricher connects to the enricher of the node. The returned function
// closes the connection.
func (r *RecorderReconciler) dialEnricher() (enricherapi.EnricherClient, func(), error) {
	conn, err := r.DialEnricher()
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to local GRPC server: %w", err)
	}

	closeConn := func() {
		if conn == nil {
			return
		}

		if err := conn.Close(); err != nil {
			r.log.Error(err, "Unable to close the enricher connection")
		}
	}

	return enricherapi.NewEnricherClient(conn), closeConn, nil
}

// releaseLogProfiles drops the data the log enricher holds for profiles.
func (r *RecorderReconciler) releaseLogProfiles(ctx context.Context, profiles []profileToCollect) {
	enricherClient, closeConn, err := r.dialEnricher()
	if err != nil {
		r.log.Error(err, "Unable to connect to the enricher for unrecordable pod")

		return
	}
	defer closeConn()

	// The log annotations only request seccomp and SELinux profiles, see
	// parseLogAnnotations, so there is no AppArmor data to reset.
	for _, prf := range profiles {
		var err error

		switch prf.kind {
		case profilerecordingapi.ProfileRecordingKindSeccompProfile:
			err = r.ResetSyscalls(
				ctx,
				enricherClient,
				&enricherapi.SyscallsRequest{Profile: prf.name},
			)
		case profilerecordingapi.ProfileRecordingKindSelinuxProfile:
			err = r.ResetAvcs(ctx, enricherClient, &enricherapi.AvcRequest{Profile: prf.name})
		case profilerecordingapi.ProfileRecordingKindAppArmorProfile:
			// parseLogAnnotations never yields it.
		}

		if err != nil {
			r.log.Error(
				err,
				"Unable to reset recorded data for unrecordable pod",
				"profile",
				prf.name,
			)
		}
	}
}

func (r *RecorderReconciler) collectProfile(
	ctx context.Context, podName types.NamespacedName, bpf *bpfRecorderSession,
) error {
	n := podName.String()

	value, ok := r.podsToWatch.Load(n)
	if !ok {
		return nil
	}

	podToWatch, ok := value.(podToWatch)
	if !ok {
		return errors.New("type assert pod to watch")
	}

	replicaSuffix := ""
	if podToWatch.baseName.Name != podName.Name &&
		strings.HasPrefix(podName.Name, podToWatch.baseName.Name) {
		// this is a replica, we need to strip the suffix from the pod name
		replicaSuffix = strings.TrimPrefix(podName.Name, podToWatch.baseName.Name)
	}

	if podToWatch.recorder == profilerecordingapi.ProfileRecorderLogs {
		if err := r.collectLogProfiles(
			ctx, replicaSuffix, podName, podToWatch.profiles, podToWatch.recordings,
		); err != nil {
			return fmt.Errorf("collect log profile: %w", err)
		}
	}

	if podToWatch.recorder == profilerecordingapi.ProfileRecorderBpf {
		if err := r.collectBpfProfiles(
			ctx,
			bpf,
			replicaSuffix,
			podName,
			podToWatch.uid,
			podToWatch.profiles,
			podToWatch.recordings,
		); err != nil {
			return fmt.Errorf("collect bpf profile: %w", err)
		}
	}

	r.podsToWatch.Delete(n)

	return nil
}

func (r *RecorderReconciler) collectLogProfiles(
	ctx context.Context,
	replicaSuffix string,
	podName types.NamespacedName,
	profiles []profileToCollect,
	recordings map[string]recordingState,
) error {
	r.log.Info("Checking if enricher is enabled")

	spod, err := r.getSPOD(ctx)
	if err != nil {
		return fmt.Errorf("getting SPOD config: %w", err)
	}

	enableLogEnricherEnv, err := strconv.ParseBool(os.Getenv(config.EnableLogEnricherEnvKey))
	if err != nil {
		enableLogEnricherEnv = false
	}

	if !ptr.Deref(spod.Spec.Enricher.EnableLogEnricher, false) && !enableLogEnricherEnv {
		return fmt.Errorf("log enricher %w", errRecorderDisabled)
	}

	r.log.Info("Connecting to local GRPC enricher server")

	enricherClient, closeConn, err := r.dialEnricher()
	if err != nil {
		return err
	}
	defer closeConn()

	for _, prf := range profiles {
		parsedProfileAnnotation, err := parseProfileAnnotation(prf.name)
		if err != nil {
			return fmt.Errorf("parse profile raw annotation: %w", err)
		}

		target, err := r.resolveProfileTarget(
			ctx, parsedProfileAnnotation, replicaSuffix, podName, recordings)
		if err != nil {
			return fmt.Errorf("resolve profile target: %w", err)
		}

		r.log.Info("Collecting profile", "name", target.name, "kind", prf.kind)

		switch prf.kind {
		case profilerecordingapi.ProfileRecordingKindSeccompProfile:
			err = r.collectLogSeccompProfile(ctx, enricherClient, target, prf.name)
		case profilerecordingapi.ProfileRecordingKindSelinuxProfile:
			err = r.collectLogSelinuxProfile(ctx, enricherClient, target, prf.name)
		case profilerecordingapi.ProfileRecordingKindAppArmorProfile:
			// parseLogAnnotations never yields it, the case keeps the switch
			// exhaustive.
			err = errors.New("log recorder doesn't support apparmor profile recording")
		default:
			err = fmt.Errorf("unrecognized kind %s", prf.kind)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

// logProfileCollector captures the type-specific operations needed for collecting
// a log-based profile, allowing the shared skeleton in collectLogProfileGeneric
// to be reused across seccomp and SELinux.
type logProfileCollector struct {
	// fetchData retrieves recorded data from the enricher. Returns (data, isEmpty, error).
	// If isEmpty is true, the profile should be reset and skipped.
	fetchData func(ctx context.Context) (any, bool, error)
	// buildProfile constructs the profile object and its spec base from the fetched data.
	buildProfile func(data any, labels map[string]string) (client.Object, *profilebase.SpecBase, error)
	// resetData resets the enricher data for further recordings.
	resetData func(ctx context.Context) error
	// profileKind is used in log and event messages (e.g. "seccomp", "selinux").
	profileKind string
}

func (r *RecorderReconciler) collectLogProfileGeneric(
	ctx context.Context,
	target *profileTarget,
	collector logProfileCollector,
) error {
	if err := r.holdRecording(ctx, target); err != nil {
		return fmt.Errorf("setting finalizer on profilerecording: %w", err)
	}

	data, isEmpty, err := collector.fetchData(ctx)
	if err != nil {
		return err
	}

	if isEmpty {
		return nil
	}

	profile, specBase, err := collector.buildProfile(data, target.labels)
	if err != nil {
		if profile != nil {
			r.record.Eventf(
				profile,
				nil,
				util.EventTypeWarning,
				reasonProfileCreationFailed,
				util.EventActionRecord,
				"%s",
				err.Error(),
			)
		}

		return err
	}

	if err := r.storeProfile(ctx, target, profile, specBase, collector.profileKind); err != nil {
		if !errors.Is(err, errProfileRejected) {
			return err
		}

		r.log.Error(err, "Dropping rejected profile", "profile", target.name.Name)
	}

	if err := collector.resetData(ctx); err != nil {
		return fmt.Errorf("reset %s data for profile %s: %w",
			collector.profileKind, target.name, err)
	}

	return nil
}

func (r *RecorderReconciler) collectLogSeccompProfile(
	ctx context.Context,
	enricherClient enricherapi.EnricherClient,
	target *profileTarget,
	profileID string,
) error {
	// Collecting stops the recording, so that the syscalls of lines read
	// afterwards are not recorded again for nobody to collect.
	request := &enricherapi.SyscallsRequest{Profile: profileID, Collect: true}
	profileNamespacedName := target.name

	collector := logProfileCollector{
		profileKind: "seccomp",
		fetchData: func(ctx context.Context) (any, bool, error) {
			response, err := r.Syscalls(ctx, enricherClient, request)
			if err != nil {
				if grpcstatus.Convert(err).Code() == grpccodes.NotFound &&
					grpcstatus.Convert(err).Message() == enricher.ErrorNoSyscalls {
					if err := r.ResetSyscalls(ctx, enricherClient, request); err != nil {
						return nil, false, fmt.Errorf(
							"reset syscalls for profile %s: %w",
							profileNamespacedName, err,
						)
					}

					r.log.Info(
						"No syscalls found, resetting profile",
						"profileID", profileID,
					)

					return nil, true, nil
				}

				return nil, false, fmt.Errorf(
					"retrieve syscalls for profile %s: %w",
					profileID, err,
				)
			}

			return response, false, nil
		},
		buildProfile: func(
			data any, labels map[string]string,
		) (client.Object, *profilebase.SpecBase, error) {
			response, ok := data.(*enricherapi.SyscallsResponse)
			if !ok {
				return nil, nil, fmt.Errorf(
					"unexpected data type: %T", data,
				)
			}

			return r.recordedSeccompProfile(
				profileNamespacedName, labels, response.GetGoArch(), response.GetSyscalls(),
			)
		},
		resetData: func(ctx context.Context) error {
			return r.ResetSyscalls(ctx, enricherClient, request)
		},
	}

	return r.collectLogProfileGeneric(ctx, target, collector)
}

func (r *RecorderReconciler) collectLogSelinuxProfile(
	ctx context.Context,
	enricherClient enricherapi.EnricherClient,
	target *profileTarget,
	profileID string,
) error {
	// Collecting stops the recording, see collectLogSeccompProfile.
	request := &enricherapi.AvcRequest{Profile: profileID, Collect: true}
	profileNamespacedName := target.name

	collector := logProfileCollector{
		profileKind: "selinux",
		fetchData: func(ctx context.Context) (any, bool, error) {
			response, err := r.Avcs(ctx, enricherClient, request)
			if err != nil {
				if grpcstatus.Convert(err).Code() == grpccodes.NotFound &&
					grpcstatus.Convert(err).Message() == enricher.ErrorNoAvcs {
					if err := r.ResetAvcs(ctx, enricherClient, request); err != nil {
						return nil, false, fmt.Errorf(
							"reset selinuxprofile for profile %s: %w",
							profileNamespacedName, err,
						)
					}

					r.log.Info(
						"No AVCs found, resetting profile",
						"profileID", profileID,
					)

					return nil, true, nil
				}

				return nil, false, fmt.Errorf(
					"retrieve avcs for profile %s: %w",
					profileID, err,
				)
			}

			return response, false, nil
		},
		buildProfile: func(
			data any, labels map[string]string,
		) (client.Object, *profilebase.SpecBase, error) {
			response, ok := data.(*enricherapi.AvcResponse)
			if !ok {
				return nil, nil, fmt.Errorf(
					"unexpected data type: %T", data,
				)
			}

			profile := &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      profileNamespacedName.Name,
					Namespace: profileNamespacedName.Namespace,
					Labels:    labels,
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Kind: selinuxprofileapi.SystemPolicyKind,
							Name: "container",
						},
					},
				},
			}

			allow, err := r.formatSelinuxProfile(profile, response)
			if err != nil {
				r.log.Error(err, "Cannot format selinuxprofile")

				return profile, nil, fmt.Errorf(
					"format selinuxprofile resource: %w", err,
				)
			}

			profile.Spec.Allow = allow

			return profile, &profile.Spec.SpecBase, nil
		},
		resetData: func(ctx context.Context) error {
			return r.ResetAvcs(ctx, enricherClient, request)
		},
	}

	return r.collectLogProfileGeneric(ctx, target, collector)
}

func (r *RecorderReconciler) formatSelinuxProfile(
	selinuxprofile *selinuxprofileapi.SelinuxProfile,
	avcResponse *enricherapi.AvcResponse,
) (selinuxprofileapi.Allow, error) {
	seBuilder := newSeProfileBuilder(selinuxprofile.GetPolicyUsage(), r.log)

	if err := seBuilder.AddAvcList(avcResponse.GetAvc()); err != nil {
		return nil, fmt.Errorf("consuming AVCs: %w", err)
	}

	sePol, err := seBuilder.Format()
	if err != nil {
		return nil, fmt.Errorf("building policy: %w", err)
	}

	return sePol, nil
}

func (r *RecorderReconciler) collectBpfProfiles(
	ctx context.Context,
	bpf *bpfRecorderSession,
	replicaSuffix string,
	podName types.NamespacedName,
	uid types.UID,
	profiles []profileToCollect,
	recordings map[string]recordingState,
) error {
	recorderClient, err := bpf.Client(ctx)
	if err != nil {
		return err
	}

	for _, profileToCollect := range profiles {
		if err := r.collectBpfProfile(
			ctx, recorderClient, replicaSuffix, podName, profileToCollect, recordings,
		); err != nil {
			return err
		}
	}

	r.log.Info("Stopping BPF recorder on node")

	if err := r.StopBpfRecorder(ctx, recorderClient, bpfRecordingRequest(uid)); err != nil {
		r.log.Error(err, "Unable to stop bpf recorder")

		return fmt.Errorf("stop bpf recorder: %w", err)
	}

	return nil
}

// bpfProfileCollector holds the kind specific parts of collecting a profile
// recorded by the BPF recorder, collectBpfProfile runs the shared steps.
type bpfProfileCollector struct {
	// kind is used in log and error messages, like "seccomp".
	kind string
	// fetch reads the recorded data and builds the profile from it. It
	// returns errRecordedProfileNotFound if nothing got recorded.
	fetch func(
		ctx context.Context, request *bpfrecorderapi.ProfileRequest, target *profileTarget,
	) (client.Object, *profilebase.SpecBase, error)
	// reset drops the recorded data in the recorder.
	reset func(ctx context.Context, request *bpfrecorderapi.ProfileRequest) error
}

// bpfProfileCollectorFor returns the collector for a profile kind, or false if
// the BPF recorder does not record that kind.
func (r *RecorderReconciler) bpfProfileCollectorFor(
	recorderClient bpfrecorderapi.BpfRecorderClient,
	kind profilerecordingapi.ProfileRecordingKind,
) (*bpfProfileCollector, bool) {
	switch kind {
	case profilerecordingapi.ProfileRecordingKindSeccompProfile:
		return &bpfProfileCollector{
			kind: "seccomp",
			fetch: func(
				ctx context.Context, request *bpfrecorderapi.ProfileRequest, target *profileTarget,
			) (client.Object, *profilebase.SpecBase, error) {
				return r.fetchSeccompBpfProfile(ctx, recorderClient, request, target)
			},
			reset: func(ctx context.Context, request *bpfrecorderapi.ProfileRequest) error {
				return r.ResetSyscallsForProfile(ctx, recorderClient, request)
			},
		}, true
	case profilerecordingapi.ProfileRecordingKindAppArmorProfile:
		return &bpfProfileCollector{
			kind: "apparmor",
			fetch: func(
				ctx context.Context, request *bpfrecorderapi.ProfileRequest, target *profileTarget,
			) (client.Object, *profilebase.SpecBase, error) {
				return r.fetchApparmorBpfProfile(ctx, recorderClient, request, target)
			},
			reset: func(ctx context.Context, request *bpfrecorderapi.ProfileRequest) error {
				return r.ResetApparmorForProfile(ctx, recorderClient, request)
			},
		}, true
	case profilerecordingapi.ProfileRecordingKindSelinuxProfile:
	}

	return nil, false
}

// collectBpfProfile stores a single profile recorded by the BPF recorder. The
// recorder only drops its data once the profile got stored, so that a failure
// on the way is retried with the complete data.
func (r *RecorderReconciler) collectBpfProfile(
	ctx context.Context,
	recorderClient bpfrecorderapi.BpfRecorderClient,
	replicaSuffix string,
	podName types.NamespacedName,
	ptc profileToCollect,
	recordings map[string]recordingState,
) error {
	collector, ok := r.bpfProfileCollectorFor(recorderClient, ptc.kind)
	if !ok {
		if ptc.kind == profilerecordingapi.ProfileRecordingKindSelinuxProfile {
			r.log.Info(
				"Profile kind not supported by BPF recorder",
				"name",
				ptc.name,
				"kind",
				ptc.kind,
			)

			return nil
		}

		return fmt.Errorf("unrecognized kind %s", ptc.kind)
	}

	parsedProfileName, err := parseProfileAnnotation(ptc.name)
	if err != nil {
		return fmt.Errorf("parse profile raw annotation: %w", err)
	}

	target, err := r.resolveProfileTarget(
		ctx,
		parsedProfileName,
		replicaSuffix,
		podName,
		recordings,
	)
	if err != nil {
		return fmt.Errorf("resolve profile target: %w", err)
	}

	// Do this BEFORE reading the syscalls to hopefully minimize the
	// race window in case reading the syscalls failed. In that case we just reconcile
	// back here and loop through again
	if err := r.holdRecording(ctx, target); err != nil {
		return fmt.Errorf("setting finalizer on profilerecording: %w", err)
	}

	r.log.Info("Collecting BPF profile", "name", ptc.name, "kind", ptc.kind)

	request := &bpfrecorderapi.ProfileRequest{Name: ptc.name}

	profile, specBase, err := collector.fetch(ctx, request, target)
	if errors.Is(err, errIncompleteRead) && r.incompleteForGood(target.attemptKey()) {
		// Waiting for data which cannot be read would keep the pod and the
		// recorder session around until the maintenance of the recorder
		// stops it. The profile is stored with what can be read instead.
		r.log.Error(err, "Collecting the recorded data which can be read", "name", ptc.name)

		request.AllowPartial = true
		profile, specBase, err = collector.fetch(ctx, request, target)
	}

	if !errors.Is(err, errIncompleteRead) {
		r.incompleteReads.Delete(target.attemptKey())
	}

	if err != nil {
		// skip empty profiles
		if errors.Is(err, errRecordedProfileNotFound) {
			return nil
		}

		return fmt.Errorf("collecting %s profile %s: %w", collector.kind, ptc.name, err)
	}

	if err := r.storeProfile(ctx, target, profile, specBase, collector.kind); err != nil {
		if !errors.Is(err, errProfileRejected) {
			return fmt.Errorf("creating/updating %s profile %s: %w", collector.kind, ptc.name, err)
		}

		// Drop the data like for a stored profile, so that the recorder
		// can be released.
		r.log.Error(err, "Dropping rejected profile", "profile", target.name.Name)
	}

	if err := collector.reset(ctx, request); err != nil {
		return fmt.Errorf("reset recorded data of %s: %w", ptc.name, err)
	}

	return nil
}

// resetBpfProfile drops the data the BPF recorder holds for a profile.
func (r *RecorderReconciler) resetBpfProfile(
	ctx context.Context,
	recorderClient bpfrecorderapi.BpfRecorderClient,
	ptc profileToCollect,
) error {
	collector, ok := r.bpfProfileCollectorFor(recorderClient, ptc.kind)
	if !ok {
		return nil
	}

	return collector.reset(ctx, &bpfrecorderapi.ProfileRequest{Name: ptc.name})
}

// bpfRecorderError maps the error of a request for recorded data by its gRPC
// status code. The BPF recorder returns NotFound if nothing got recorded for
// the profile, this might be an init container which is no longer active, so
// that the profile is skipped. FailedPrecondition means that the recorder
// cannot provide the data at all, which releases the pod. DataLoss means that
// some of the recorded data cannot be read.
func (r *RecorderReconciler) bpfRecorderError(err error, what, profile string) error {
	code := grpcstatus.Code(err)

	if code == grpccodes.NotFound {
		r.log.Error(err, "Recorded profile not found", "name", profile)

		return errRecordedProfileNotFound
	}

	if code == grpccodes.FailedPrecondition {
		return fmt.Errorf("getting %s for profile: %w: %s",
			what, errBpfRecorderUnavailable, grpcstatus.Convert(err).Message())
	}

	if code == grpccodes.DataLoss {
		return fmt.Errorf("getting %s for profile: %w: %s",
			what, errIncompleteRead, grpcstatus.Convert(err).Message())
	}

	return fmt.Errorf("getting %s for profile: %w", what, err)
}

func (r *RecorderReconciler) fetchSeccompBpfProfile(
	ctx context.Context,
	recorderClient bpfrecorderapi.BpfRecorderClient,
	request *bpfrecorderapi.ProfileRequest,
	target *profileTarget,
) (client.Object, *profilebase.SpecBase, error) {
	response, err := r.SyscallsForProfile(ctx, recorderClient, request)
	if err != nil {
		return nil, nil, r.bpfRecorderError(err, "syscalls", request.GetName())
	}

	profile, specBase, err := r.recordedSeccompProfile(
		target.name, target.labels, response.GetGoArch(), response.GetSyscalls(),
	)
	if err == nil && response.GetIncomplete() {
		r.log.Info("Some recorded syscalls cannot be read, the profile may be incomplete",
			"profile", target.name.Name)
		r.record.Eventf(
			profile,
			nil,
			util.EventTypeWarning,
			reasonRecordingIncomplete,
			util.EventActionRecord,
			"Some recorded syscalls cannot be read, the profile may be incomplete",
		)
	}

	return profile, specBase, err
}

// recordedSeccompProfile returns the profile which allows the recorded
// syscalls of the architecture goArch.
func (r *RecorderReconciler) recordedSeccompProfile(
	name types.NamespacedName, labels map[string]string, goArch string, syscalls []string,
) (client.Object, *profilebase.SpecBase, error) {
	arch, err := r.goArchToSeccompArch(goArch)
	if err != nil {
		return nil, nil, fmt.Errorf("getting seccomp arch: %w", err)
	}

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name.Name,
			Namespace: name.Namespace,
			Labels:    labels,
		},
		Spec: seccompprofileapi.SeccompProfileSpec{
			DefaultAction: seccompprofileapi.ActErrno,
			Architectures: []seccompprofileapi.Arch{arch},
			Syscalls: []seccompprofileapi.Syscall{{
				Action: seccompprofileapi.ActAllow,
				Names:  syscalls,
			}},
		},
	}

	return profile, &profile.Spec.SpecBase, nil
}

func (r *RecorderReconciler) fetchApparmorBpfProfile(
	ctx context.Context,
	recorderClient bpfrecorderapi.BpfRecorderClient,
	request *bpfrecorderapi.ProfileRequest,
	target *profileTarget,
) (client.Object, *profilebase.SpecBase, error) {
	response, err := r.ApparmorForProfile(ctx, recorderClient, request)
	if err != nil {
		return nil, nil, r.bpfRecorderError(err, "apparmor rules", request.GetName())
	}

	profile := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      target.name.Name,
			Namespace: target.name.Namespace,
			Labels:    target.labels,
		},
		Spec: apparmorprofileapi.AppArmorProfileSpec{
			Abstract: r.generateAppArmorProfileAbstract(response),
		},
	}

	return profile, &profile.Spec.SpecBase, nil
}

func (r *RecorderReconciler) generateAppArmorProfileAbstract(
	response *bpfrecorderapi.ApparmorResponse,
) apparmorprofileapi.AppArmorAbstract {
	return crd2armor.AbstractFromRecording(&crd2armor.RecordedAccess{
		AllowedExecutables: response.GetFiles().GetAllowedExecutables(),
		AllowedLibraries:   response.GetFiles().GetAllowedLibraries(),
		ReadOnlyPaths:      response.GetFiles().GetReadonlyPaths(),
		WriteOnlyPaths:     response.GetFiles().GetWriteonlyPaths(),
		ReadWritePaths:     response.GetFiles().GetReadwritePaths(),
		UseRaw:             response.GetSocket().GetUseRaw(),
		UseTCP:             response.GetSocket().GetUseTcp(),
		UseUDP:             response.GetSocket().GetUseUdp(),
		Capabilities:       response.GetCapabilities(),
	})
}

type parsedAnnotation struct {
	profileName string
	cntName     string
	nonce       string
	timestamp   string
}

func parseProfileAnnotation(annotation string) (*parsedAnnotation, error) {
	const expectedParts = 4

	parts := strings.Split(annotation, "_")
	if len(parts) != expectedParts {
		return nil,
			fmt.Errorf(
				"invalid annotation: %s, expected %d parts got %d",
				annotation,
				expectedParts,
				len(parts),
			)
	}

	return &parsedAnnotation{
		profileName: parts[0],
		cntName:     parts[1],
		nonce:       parts[2], // unused for now, but we might need it in the future
		timestamp:   parts[3], // unused for now, but let's keep it for future use
	}, nil
}

func createProfileName(cntName, replicaSuffix, namespace, profileName string) types.NamespacedName {
	name := fmt.Sprintf("%s-%s", profileName, cntName)
	if replicaSuffix != "" {
		name = fmt.Sprintf("%s-%s", name, replicaSuffix)
	}

	return types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
}

// profileTarget describes where and how a collected profile is stored.
type profileTarget struct {
	name          types.NamespacedName
	labels        map[string]string
	recordingName string
	state         recordingState
	// recording is nil if the recording does not exist any more.
	recording *profilerecordingapi.ProfileRecording
	// merge stores the profile merged into the final profile of the recording
	// instead of as a partial profile. Nothing would merge a partial profile
	// any more once its recording is gone, or about to be gone without
	// waiting for it.
	merge bool
	// partialName is the name of the partial profile stored if merging fails.
	partialName types.NamespacedName
	// pod is the recorded pod.
	pod types.NamespacedName
}

func (t *profileTarget) attemptKey() attemptKey {
	return attemptKey{pod: t.pod, profile: t.name}
}

// resolveProfileTarget determines how the profile for the parsed annotation is
// stored. The recording is looked up again, as it is authoritative, but the
// state captured when the pod started being recorded is used once it is gone.
func (r *RecorderReconciler) resolveProfileTarget(
	ctx context.Context,
	parsed *parsedAnnotation,
	replicaSuffix string,
	podName types.NamespacedName,
	recordings map[string]recordingState,
) (*profileTarget, error) {
	if errs := validation.IsDNS1123Label(parsed.profileName); len(errs) > 0 {
		return nil, errNameNotValid
	}

	target := &profileTarget{recordingName: parsed.profileName, pod: podName}
	recording := &profilerecordingapi.ProfileRecording{}

	err := r.ClientGet(
		ctx,
		r.client,
		client.ObjectKey{Name: parsed.profileName, Namespace: podName.Namespace},
		recording,
	)

	switch {
	case kerrors.IsNotFound(err):
		state, ok := recordings[parsed.profileName]
		if !ok {
			// Nothing tells how the recording wanted its profiles stored.
			return nil, errRecordingGone
		}

		target.state = state
		target.merge = state.partial
	case err != nil:
		return nil, fmt.Errorf("get recording: %w", err)
	default:
		target.recording = recording
		target.state = recordingStateOf(recording)

		// The merger may already be done with a recording which is being
		// deleted, and nothing would merge a partial profile stored now.
		target.merge = target.state.partial && !recording.GetDeletionTimestamp().IsZero()
	}

	partial := target.state.partial && !target.merge

	partialSuffix := replicaSuffix
	if partialSuffix == "" {
		partialSuffix = podName.Name
	}

	switch {
	case target.merge:
		// The name the recording merger gives the merged profile.
		replicaSuffix = ""
		target.partialName = createProfileName(
			parsed.cntName,
			partialSuffix,
			podName.Namespace,
			parsed.profileName,
		)
	case partial:
		replicaSuffix = partialSuffix
	}

	target.name = createProfileName(
		parsed.cntName,
		replicaSuffix,
		podName.Namespace,
		parsed.profileName,
	)
	target.labels = map[string]string{
		profilerecordingapi.ProfileToRecordingLabel:          parsed.profileName,
		profilerecordingapi.ProfileToContainerLabel:          parsed.cntName,
		profilerecordingapi.ProfileToRecordingNamespaceLabel: podName.Namespace,
	}

	if partial {
		target.labels[profilebase.ProfilePartialLabel] = "true"
	}

	return target, nil
}

// holdRecording adds the finalizer which keeps the recording around until its
// partial profiles are merged.
func (r *RecorderReconciler) holdRecording(ctx context.Context, target *profileTarget) error {
	recording := target.recording
	if !target.state.partial || target.merge || recording == nil {
		return nil
	}

	if controllerutil.ContainsFinalizer(
		recording,
		profilerecordingapi.RecordingHasUnmergedProfiles,
	) {
		return nil
	}

	// The API server rejects adding finalizers to an object which is being
	// deleted, so retrying would never succeed.
	if !recording.GetDeletionTimestamp().IsZero() {
		r.log.Info("Not adding finalizer to recording being deleted",
			"recording", recording.Name, "namespace", recording.Namespace)

		return nil
	}

	controllerutil.AddFinalizer(recording, profilerecordingapi.RecordingHasUnmergedProfiles)

	if err := r.client.Update(ctx, recording); err != nil {
		return fmt.Errorf("update recording: %w", err)
	}

	return nil
}

// storeProfile creates or updates the collected profile as target describes.
func (r *RecorderReconciler) storeProfile(
	ctx context.Context,
	target *profileTarget,
	profile client.Object,
	specBase *profilebase.SpecBase,
	kind string,
) error {
	if target.state.disable {
		specBase.State = profilebase.SpecStateDisabled
	}

	desired, ok := profile.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("object %T is not a client.Object", profile)
	}

	var res controllerutil.OperationResult

	// Several nodes can merge into the same profile at once. The merge is
	// done against the object fetched right before the update, which fails
	// on a conflicting write in between and is then done again.
	err := retry.OnError(storeProfileBackoff, func(err error) bool {
		return kerrors.IsConflict(err) || kerrors.IsAlreadyExists(err)
	}, func() error {
		stored, ok := desired.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("object %T is not a client.Object", desired)
		}

		var err error

		res, err = r.CreateOrUpdate(ctx, r.client, stored, func() error {
			if err := util.CheckRecordingOwner(
				stored, target.recordingName, target.name.Namespace,
			); err != nil {
				return fmt.Errorf("check profile owner: %w", err)
			}

			// Profiles recorded by an older version miss the labels which
			// were added since.
			labels := stored.GetLabels()
			if labels == nil {
				labels = map[string]string{}
			}

			maps.Copy(labels, desired.GetLabels())
			stored.SetLabels(labels)

			spec := desired
			if target.merge {
				if spec, err = mergeStoredProfile(stored, desired); err != nil {
					return fmt.Errorf("%w: %w", errMergeFailed, err)
				}
			}

			return copySpec(stored, spec)
		})

		return err
	})
	if errors.Is(err, errMergeFailed) {
		return r.storePartialProfile(ctx, target, profile, kind, err)
	}

	if err != nil {
		r.log.Error(err, "Cannot create profile resource")
		r.record.Eventf(
			profile,
			nil,
			util.EventTypeWarning,
			reasonProfileCreationFailed,
			util.EventActionRecord,
			"%s",
			err.Error(),
		)

		// Retrying cannot resolve the conflict, so drop the recorded data.
		if errors.Is(err, util.ErrProfileOwnedByOtherRecording) {
			return nil
		}

		if r.rejectedForGood(target.attemptKey(), err) {
			return fmt.Errorf("%w: %w", errProfileRejected, err)
		}

		return fmt.Errorf("create %s profile resource: %w", kind, err)
	}

	r.forbiddenAttempts.Delete(target.attemptKey())

	r.log.Info("Created/updated profile", "action", res, "name", target.name.Name)
	r.record.Eventf(
		profile,
		nil,
		util.EventTypeNormal,
		reasonProfileCreated,
		util.EventActionRecord,
		"%s",
		kind+" profile created",
	)

	return nil
}

// storePartialProfile stores the profile as a partial one after merging it
// failed. Merging would fail again, so the recorded data is kept this way
// instead of being retried for good.
func (r *RecorderReconciler) storePartialProfile(
	ctx context.Context,
	target *profileTarget,
	profile client.Object,
	kind string,
	mergeErr error,
) error {
	r.log.Error(mergeErr, "Cannot merge profile, storing it as partial profile",
		"profile", target.name.Name, "partialProfile", target.partialName.Name)
	r.record.Eventf(
		profile,
		nil,
		util.EventTypeWarning,
		reasonProfileMergeFailed,
		util.EventActionRecord,
		"%s",
		mergeErr.Error(),
	)

	target.merge = false
	target.name = target.partialName
	target.labels = maps.Clone(target.labels)
	target.labels[profilebase.ProfilePartialLabel] = "true"

	partial, ok := profile.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("object %T is not a client.Object", profile)
	}

	partial.SetName(target.name.Name)
	partial.SetLabels(target.labels)

	return r.storeProfile(ctx, target, partial, specBaseOf(partial), kind)
}

const (
	// maxForbiddenAttempts is how often storing a profile is tried at least
	// when the API server forbids it, which can also be caused by a
	// permission not granted yet.
	maxForbiddenAttempts = 5
	// defaultForbiddenGracePeriod is the time a granted permission takes at
	// most to be in effect. The rate limiter of the controller retries within
	// a fraction of a second, so the attempts alone do not cover it.
	defaultForbiddenGracePeriod = 2 * time.Minute

	// maxIncompleteReadAttempts is how often reading the recorded data of
	// a profile is tried at least while the BPF recorder cannot read all of
	// it.
	maxIncompleteReadAttempts = 5
	// defaultIncompleteReadGracePeriod is how long reading the recorded data
	// is tried at least, so that a short failure does not cost data.
	defaultIncompleteReadGracePeriod = time.Minute
)

// failedAttempts counts the failed attempts to collect or store a profile.
type failedAttempts struct {
	count atomic.Int32
	first time.Time
}

// failedForGood counts a failed attempt for key in attempts. It reports
// whether at least maxAttempts failed, the first at least gracePeriod ago, and
// then forgets the attempts.
func failedForGood(
	attempts *sync.Map, key attemptKey, maxAttempts int32, gracePeriod time.Duration,
) bool {
	value, _ := attempts.LoadOrStore(key, &failedAttempts{first: time.Now()})

	failed, ok := value.(*failedAttempts)
	if !ok || (failed.count.Add(1) >= maxAttempts && time.Since(failed.first) >= gracePeriod) {
		attempts.Delete(key)

		return true
	}

	return false
}

// incompleteForGood reports whether the BPF recorder failed to read all the
// data recorded for a profile often and long enough to give up on it.
func (r *RecorderReconciler) incompleteForGood(key attemptKey) bool {
	return failedForGood(
		&r.incompleteReads, key, maxIncompleteReadAttempts, r.incompleteReadGracePeriod,
	)
}

// rejectedForGood reports whether the API server will reject the profile
// again, in which case retrying would only keep the recording going for good.
func (r *RecorderReconciler) rejectedForGood(key attemptKey, err error) bool {
	if kerrors.IsInvalid(err) || kerrors.IsRequestEntityTooLargeError(err) ||
		kerrors.IsBadRequest(err) {
		return true
	}

	if !kerrors.IsForbidden(err) {
		return false
	}

	return failedForGood(&r.forbiddenAttempts, key, maxForbiddenAttempts, r.forbiddenGracePeriod)
}

// mergeStoredProfile returns desired merged with the stored profile, the way
// the recording merger does it for partial profiles. A profile of anything
// else than the recording is not merged: storing replaces it, or is rejected
// as it belongs to another recording.
func mergeStoredProfile(stored, desired client.Object) (client.Object, error) {
	if stored.GetResourceVersion() == "" {
		return desired, nil
	}

	if _, recorded := stored.GetLabels()[profilerecordingapi.ProfileToRecordingLabel]; !recorded {
		return desired, nil
	}

	merged, err := recordingmerger.MergeProfiles([]client.Object{stored, desired})
	if err != nil {
		return nil, fmt.Errorf("merge with stored profile: %w", err)
	}

	specBaseOf(merged).State = specBaseOf(desired).State

	return merged, nil
}

// specBaseOf returns the base spec of a recorded profile.
func specBaseOf(obj client.Object) *profilebase.SpecBase {
	switch p := obj.(type) {
	case *seccompprofileapi.SeccompProfile:
		return &p.Spec.SpecBase
	case *selinuxprofileapi.SelinuxProfile:
		return &p.Spec.SpecBase
	case *apparmorprofileapi.AppArmorProfile:
		return &p.Spec.SpecBase
	default:
		return &profilebase.SpecBase{}
	}
}

// copySpec sets the spec of dst to the one of src.
func copySpec(dst, src client.Object) error {
	switch d := dst.(type) {
	case *seccompprofileapi.SeccompProfile:
		if s, ok := src.(*seccompprofileapi.SeccompProfile); ok {
			s.Spec.DeepCopyInto(&d.Spec)

			return nil
		}
	case *selinuxprofileapi.SelinuxProfile:
		if s, ok := src.(*selinuxprofileapi.SelinuxProfile); ok {
			s.Spec.DeepCopyInto(&d.Spec)

			return nil
		}
	case *apparmorprofileapi.AppArmorProfile:
		if s, ok := src.(*apparmorprofileapi.AppArmorProfile); ok {
			s.Spec.DeepCopyInto(&d.Spec)

			return nil
		}
	}

	return fmt.Errorf("cannot copy the spec of %T to %T", src, dst)
}

// annotationKind maps an annotation key prefix to the profile kind it records.
type annotationKind struct {
	prefix string
	kind   profilerecordingapi.ProfileRecordingKind
}

// parseAnnotations parses the provided annotations and extracts the mandatory
// output profiles for the recorder described by kinds.
//
// The profiles are ordered by their annotation key, so that the order of the
// recording and collection does not change from one reconcile to the next.
func parseAnnotations(
	annotations map[string]string, kinds []annotationKind,
) (res []profileToCollect, err error) {
	for _, key := range slices.Sorted(maps.Keys(annotations)) {
		profile := annotations[key]

		var collectProfile profileToCollect

		matched := false

		for _, k := range kinds {
			if strings.HasPrefix(key, k.prefix) {
				collectProfile.kind = k.kind
				matched = true

				break
			}
		}

		if !matched {
			continue
		}

		if profile == "" {
			return nil, fmt.Errorf(
				"%w: providing output profile is mandatory",
				errInvalidAnnotation,
			)
		}

		collectProfile.name = profile

		res = append(res, collectProfile)
	}

	return res, nil
}

// parseLogAnnotations parses the provided annotations and extracts the
// mandatory output profiles for the log recorder.
func parseLogAnnotations(annotations map[string]string) ([]profileToCollect, error) {
	return parseAnnotations(annotations, []annotationKind{
		{
			config.SeccompProfileRecordLogsAnnotationKey,
			profilerecordingapi.ProfileRecordingKindSeccompProfile,
		},
		{
			config.SelinuxProfileRecordLogsAnnotationKey,
			profilerecordingapi.ProfileRecordingKindSelinuxProfile,
		},
	})
}

// parseBpfAnnotations parses the provided annotations and extracts the
// mandatory output profiles for the bpf recorder.
func parseBpfAnnotations(annotations map[string]string) ([]profileToCollect, error) {
	return parseAnnotations(annotations, []annotationKind{
		{
			config.SeccompProfileRecordBpfAnnotationKey,
			profilerecordingapi.ProfileRecordingKindSeccompProfile,
		},
		{
			config.ApparmorProfileRecordBpfAnnotationKey,
			profilerecordingapi.ProfileRecordingKindAppArmorProfile,
		},
	})
}

type seProfileBuilder struct {
	permMap       map[string]sets.Set[string]
	usageCtx      string
	policyBuilder selinuxprofileapi.Allow
	log           logr.Logger
	// used to optimize sorting
	keys []string
}

func newSeProfileBuilder(usageCtx string, log logr.Logger) *seProfileBuilder {
	return &seProfileBuilder{
		permMap:       make(map[string]sets.Set[string]),
		usageCtx:      usageCtx,
		policyBuilder: make(selinuxprofileapi.Allow),
		log:           log,
		keys:          make([]string, 0),
	}
}

func (sb *seProfileBuilder) AddAvcList(avcs []*enricherapi.AvcResponse_SelinuxAvc) error {
	for _, avc := range avcs {
		sb.log.Info("Received an AVC response",
			"perm", avc.GetPerm(), "tclass",
			avc.GetTclass(), "scontext", avc.GetScontext(),
			"tcontext", avc.GetTcontext())

		if err := sb.addAvc(avc); err != nil {
			return fmt.Errorf("adding AVC: %w", err)
		}
	}

	return nil
}

func (sb *seProfileBuilder) addAvc(avc *enricherapi.AvcResponse_SelinuxAvc) error {
	ctxType, err := ctxt2type(avc.GetTcontext())
	if err != nil {
		return fmt.Errorf("converting context to type: %w", err)
	}

	key := avc.GetTclass() + " " + ctxType

	perms, ok := sb.permMap[key]
	if ok {
		perms.Insert(avc.GetPerm())
	} else {
		sb.permMap[key] = sets.New(avc.GetPerm())
		// Once per key, a recording has many AVCs of the same kind.
		sb.keys = append(sb.keys, key)
	}

	return nil
}

func (sb *seProfileBuilder) Format() (selinuxprofileapi.Allow, error) {
	slices.Sort(sb.keys)

	for _, key := range sb.keys {
		val := sb.permMap[key]
		if err := sb.writeLineFromKeyVal(key, val); err != nil {
			return nil, fmt.Errorf("writing policy line from key-value pair: %w", err)
		}
	}

	return sb.policyBuilder, nil
}

func (sb *seProfileBuilder) writeLineFromKeyVal(key string, val sets.Set[string]) error {
	tclass, setype := sb.targetClassCtx(key)
	if tclass == "" || setype == "" {
		return errors.New("empty context or class")
	}

	// If we haven't parsed the type, ensure we have space for it
	_, haveType := sb.policyBuilder[selinuxprofileapi.LabelKey(setype)]
	if !haveType {
		sb.policyBuilder[selinuxprofileapi.LabelKey(setype)] = make(
			map[selinuxprofileapi.ObjectClassKey]selinuxprofileapi.PermissionSet)
	}

	typePerms := sb.policyBuilder[selinuxprofileapi.LabelKey(setype)]
	l := val.UnsortedList()
	slices.Sort(l)
	typePerms[selinuxprofileapi.ObjectClassKey(tclass)] = selinuxprofileapi.PermissionSet(l)

	return nil
}

func (sb *seProfileBuilder) targetClassCtx(key string) (tclass, tcontext string) {
	splitkey := strings.Split(key, " ")
	tclass = splitkey[0]

	tcontext = splitkey[1]
	if tcontext == config.SelinuxPermissiveProfile {
		// rewrite the context to reference itself.
		// We replace this when writing the policy.
		tcontext = selinuxprofileapi.AllowSelf
	}

	return
}

func ctxt2type(ctx string) (string, error) {
	elems := strings.Split(ctx, ":")
	if len(elems) < seContextRequiredParts {
		return "", errors.New("malformed SELinux context")
	}

	return elems[2], nil
}

func (r *RecorderReconciler) goArchToSeccompArch(goarch string) (seccompprofileapi.Arch, error) {
	seccompArch, err := r.GoArchToSeccompArch(goarch)
	if err != nil {
		return "", fmt.Errorf("convert golang to seccomp arch: %w", err)
	}

	return seccompprofileapi.Arch(seccompArch), nil
}
