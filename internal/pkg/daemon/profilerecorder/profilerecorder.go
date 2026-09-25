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
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/recordingmerger"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
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

	seContextRequiredParts = 3
)

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
)

// unrecordable reports whether a collect error means the pod can never be
// collected, so that the reconciler releases it instead of requeuing forever.
func unrecordable(err error) bool {
	return errors.Is(err, errNameNotValid) || errors.Is(err, errRecordingGone)
}

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &RecorderReconciler{
		impl: &defaultImpl{},
	}
}

type RecorderReconciler struct {
	impl
	client        client.Client
	log           logr.Logger
	record        util.EventRecorder
	nodeAddresses []string
	podsToWatch   sync.Map
	// forbiddenAttempts counts per profile how often storing it was
	// forbidden.
	forbiddenAttempts sync.Map
}

type profileToCollect struct {
	kind profilerecordingapi.ProfileRecordingKind
	name string
}

type podToWatch struct {
	baseName types.NamespacedName
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

	r.client = r.ManagerGetClient(mgr)
	r.nodeAddresses = nodeAddresses
	r.record = r.ManagerGetEventRecorder(mgr, name)

	return r.NewControllerManagedBy(
		mgr, name, r.isPodWithTraceAnnotation, r.isPodOnLocalNode, r,
	)
}

func (r *RecorderReconciler) getSPOD(
	ctx context.Context,
) (*spodapi.SecurityProfilesOperatorDaemon, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	return r.GetSPOD(ctx, r.client)
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

// authorizedProfiles drops the profiles whose annotation is not backed by a
// ProfileRecording that selects this pod.
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

	recordings, err := r.ListRecordings(ctx, r.client, pod.Namespace)
	if err != nil {
		return nil, nil, fmt.Errorf("list profile recordings: %w", err)
	}

	podLabels := k8slabels.Set(pod.GetLabels())
	authorized := make([]profileToCollect, 0, len(profiles))
	states := map[string]recordingState{}

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

			continue
		}

		if recording := r.recordingAuthorizes(
			recordings, podLabels, parsed, profile.kind, recorder,
		); recording != nil {
			authorized = append(authorized, profile)
			states[recording.Name] = recordingStateOf(recording)

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

	pod, err := r.GetPod(ctx, r.client, req.NamespacedName)
	if err != nil {
		if kerrors.IsNotFound(err) {
			collErr := r.collectProfile(ctx, req.NamespacedName)
			if unrecordable(collErr) {
				logger.Error(collErr, "cannot collect profile")
				// Not reconcilable, so nothing will ever collect this pod:
				// release it rather than leaking the watch and the recorder.
				r.releaseUnrecordablePod(ctx, req.NamespacedName)

				return reconcile.Result{}, nil
			} else if collErr != nil {
				return reconcile.Result{}, fmt.Errorf(
					"collect profile for removed pod: %w",
					collErr,
				)
			}

			return reconcile.Result{}, nil
		}

		// Returning an error means we will be requeued implicitly.
		logger.Error(err, "Error reading pod")

		return reconcile.Result{}, fmt.Errorf("cannot get pod: %w", err)
	}

	// Pods are normally picked up while pending. A running pod which is not
	// tracked yet was missed, for example because the daemon restarted, and
	// is still recorded rather than never.
	if pod.Status.Phase == corev1.PodPending || pod.Status.Phase == corev1.PodRunning {
		if _, ok := r.podsToWatch.Load(req.String()); ok {
			// We're tracking this pod already
			return reconcile.Result{}, nil
		}

		logProfiles, err := parseLogAnnotations(pod.Annotations)
		if err != nil {
			// Malformed annotations could be set by users directly, which is
			// why we are ignoring them.
			logger.Info("Ignoring because unable to parse log annotation", "error", err)
			r.record.Eventf(
				pod,
				nil,
				util.EventTypeWarning,
				reasonAnnotationParsing,
				util.EventActionRecord,
				"%s",
				err.Error(),
			)

			return reconcile.Result{}, nil
		}

		bpfProfiles, err := parseBpfAnnotations(pod.Annotations)
		if err != nil {
			// Malformed annotations could be set by users directly, which is
			// why we are ignoring them.
			logger.Info("Ignoring because unable to parse bpf annotation", "error", err)
			r.record.Eventf(
				pod,
				nil,
				util.EventTypeWarning,
				reasonAnnotationParsing,
				util.EventActionRecord,
				"%s",
				err.Error(),
			)

			return reconcile.Result{}, nil
		}

		var (
			profiles []profileToCollect
			recorder profilerecordingapi.ProfileRecorder
		)

		switch {
		case len(logProfiles) > 0:
			profiles = logProfiles
			recorder = profilerecordingapi.ProfileRecorderLogs
		case len(bpfProfiles) > 0:
			profiles = bpfProfiles
			recorder = profilerecordingapi.ProfileRecorderBpf
		default:
			logger.Info("No log or bpf annotations found on pod")

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
			if err := r.startBpfRecorder(ctx); err != nil {
				logger.Error(err, "unable to start bpf recorder")

				return reconcile.Result{}, err
			}
		}

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
			podToWatch{baseName, recorder, profiles, recordings},
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

	if pod.Status.Phase == corev1.PodSucceeded {
		collErr := r.collectProfile(ctx, req.NamespacedName)
		if unrecordable(collErr) {
			logger.Error(collErr, "cannot collect profile")
			// Not reconcilable, so nothing will ever collect this pod:
			// release it rather than leaking the watch and the recorder.
			r.releaseUnrecordablePod(ctx, req.NamespacedName)

			return reconcile.Result{}, nil
		} else if collErr != nil {
			return reconcile.Result{}, fmt.Errorf("collect profile for succeeded pod: %w", collErr)
		}
	}

	return reconcile.Result{}, nil
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
		return nil, nil, errors.New("bpf recorder is not enabled")
	}

	r.log.Info("Connecting to local GRPC bpf recorder server")

	conn, err := r.DialBpfRecorder()
	if err != nil {
		return nil, nil, fmt.Errorf("connect to bpf recorder GRPC server: %w", err)
	}

	bpfRecorderClient := bpfrecorderapi.NewBpfRecorderClient(conn)

	return bpfRecorderClient, conn, nil
}

func (r *RecorderReconciler) startBpfRecorder(ctx context.Context) error {
	recorderClient, conn, err := r.getBpfRecorderClient(ctx)
	if err != nil {
		return fmt.Errorf("get bpf recorder client: %w", err)
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	r.log.Info("Starting BPF recorder on node")

	return r.StartBpfRecorder(ctx, recorderClient)
}

func (r *RecorderReconciler) stopBpfRecorder(ctx context.Context) error {
	recorderClient, conn, err := r.getBpfRecorderClient(ctx)
	if err != nil {
		return fmt.Errorf("get bpf recorder client: %w", err)
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	r.log.Info("Stopping BPF recorder on node")

	return r.StopBpfRecorder(ctx, recorderClient)
}

// releaseUnrecordablePod drops a pod whose profiles can never be collected. It
// must undo whatever Reconcile set up, otherwise the watch entry leaks, the
// recorded data stays in the recorders until they are full and, for the BPF
// recorder, the node stays armed for the lifetime of the daemon.
func (r *RecorderReconciler) releaseUnrecordablePod(
	ctx context.Context, podName types.NamespacedName,
) {
	n := podName.String()

	value, ok := r.podsToWatch.Load(n)
	if !ok {
		return
	}

	if podToWatch, ok := value.(podToWatch); ok {
		switch podToWatch.recorder {
		case profilerecordingapi.ProfileRecorderBpf:
			r.releaseBpfProfiles(ctx, podToWatch.profiles)
		case profilerecordingapi.ProfileRecorderLogs:
			r.releaseLogProfiles(ctx, podToWatch.profiles)
		}
	}

	r.podsToWatch.Delete(n)
}

// releaseBpfProfiles drops the data the BPF recorder holds for profiles and
// stops the recorder.
func (r *RecorderReconciler) releaseBpfProfiles(ctx context.Context, profiles []profileToCollect) {
	recorderClient, conn, err := r.getBpfRecorderClient(ctx)
	if err != nil {
		r.log.Error(err, "Unable to release bpf recorder for unrecordable pod")

		return
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

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

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	if err := r.StopBpfRecorder(ctx, recorderClient); err != nil {
		r.log.Error(err, "Unable to stop bpf recorder for unrecordable pod")
	}
}

// releaseLogProfiles drops the data the log enricher holds for profiles.
func (r *RecorderReconciler) releaseLogProfiles(ctx context.Context, profiles []profileToCollect) {
	conn, err := r.DialEnricher()
	if err != nil {
		r.log.Error(err, "Unable to connect to the enricher for unrecordable pod")

		return
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	enricherClient := enricherapi.NewEnricherClient(conn)

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
			continue
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
	ctx context.Context, podName types.NamespacedName,
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
			ctx, replicaSuffix, podName, podToWatch.profiles, podToWatch.recordings,
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
		return errors.New("log enricher not enabled")
	}

	r.log.Info("Connecting to local GRPC enricher server")

	conn, err := r.DialEnricher()
	if err != nil {
		return fmt.Errorf("connecting to local GRPC server: %w", err)
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	enricherClient := enricherapi.NewEnricherClient(conn)

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
	request := &enricherapi.SyscallsRequest{Profile: profileID}
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

			arch, err := r.goArchToSeccompArch(response.GetGoArch())
			if err != nil {
				return nil, nil, fmt.Errorf("get seccomp arch: %w", err)
			}

			profile := &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      profileNamespacedName.Name,
					Namespace: profileNamespacedName.Namespace,
					Labels:    labels,
				},
				Spec: seccompprofileapi.SeccompProfileSpec{
					DefaultAction: seccompprofileapi.ActErrno,
					Architectures: []seccompprofileapi.Arch{arch},
					Syscalls: []seccompprofileapi.Syscall{{
						Action: seccompprofileapi.ActAllow,
						Names:  response.GetSyscalls(),
					}},
				},
			}

			return profile, &profile.Spec.SpecBase, nil
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
	request := &enricherapi.AvcRequest{Profile: profileID}
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
	replicaSuffix string,
	podName types.NamespacedName,
	profiles []profileToCollect,
	recordings map[string]recordingState,
) error {
	recorderClient, conn, err := r.getBpfRecorderClient(ctx)
	if err != nil {
		return fmt.Errorf("get bpf recorder client: %w", err)
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	for _, profileToCollect := range profiles {
		if err := r.collectBpfProfile(
			ctx, recorderClient, replicaSuffix, podName, profileToCollect, recordings,
		); err != nil {
			return err
		}
	}

	if err := r.stopBpfRecorder(ctx); err != nil {
		r.log.Error(err, "Unable to stop bpf recorder")

		return fmt.Errorf("stop bpf recorder: %w", err)
	}

	return nil
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
	if ptc.kind == profilerecordingapi.ProfileRecordingKindSelinuxProfile {
		r.log.Info(
			"Profile kind not supported by BPF recoder",
			"name",
			ptc.name,
			"kind",
			ptc.kind,
		)

		return nil
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

	var (
		profile  client.Object
		specBase *profilebase.SpecBase
		kind     string
	)

	switch ptc.kind {
	case profilerecordingapi.ProfileRecordingKindSeccompProfile:
		seccompProfile, err := r.collectSeccompBpfProfile(
			ctx,
			recorderClient,
			&ptc,
			target.name,
			target.labels,
		)
		if err != nil {
			// skip empty profiles
			if errors.Is(err, errRecordedProfileNotFound) {
				return nil
			}

			return fmt.Errorf("collecting seccomp profile %s: %w", ptc.name, err)
		}

		profile, specBase, kind = seccompProfile, &seccompProfile.Spec.SpecBase, "seccomp"
	case profilerecordingapi.ProfileRecordingKindAppArmorProfile:
		apparmorProfile, err := r.collectApparmorBpfProfile(
			ctx,
			recorderClient,
			&ptc,
			target.name,
			target.labels,
		)
		if err != nil {
			// skip empty profiles
			if errors.Is(err, errRecordedProfileNotFound) {
				return nil
			}

			return fmt.Errorf("collecting apparmor profile %s: %w", ptc.name, err)
		}

		profile, specBase, kind = apparmorProfile, &apparmorProfile.Spec.SpecBase, "apparmor"
	case profilerecordingapi.ProfileRecordingKindSelinuxProfile:
		// Skipped above.
		return nil
	default:
		return fmt.Errorf("unrecognized kind %s", ptc.kind)
	}

	if err := r.storeProfile(ctx, target, profile, specBase, kind); err != nil {
		if !errors.Is(err, errProfileRejected) {
			return fmt.Errorf("creating/updating %s profile %s: %w", kind, ptc.name, err)
		}

		// Drop the data like for a stored profile, so that the recorder
		// can be released.
		r.log.Error(err, "Dropping rejected profile", "profile", target.name.Name)
	}

	if err := r.resetBpfProfile(ctx, recorderClient, ptc); err != nil {
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
	request := &bpfrecorderapi.ProfileRequest{Name: ptc.name}

	switch ptc.kind {
	case profilerecordingapi.ProfileRecordingKindSeccompProfile:
		return r.ResetSyscallsForProfile(ctx, recorderClient, request)
	case profilerecordingapi.ProfileRecordingKindAppArmorProfile:
		return r.ResetApparmorForProfile(ctx, recorderClient, request)
	case profilerecordingapi.ProfileRecordingKindSelinuxProfile:
	}

	return nil
}

func (r *RecorderReconciler) collectSeccompBpfProfile(
	ctx context.Context,
	recorderClient bpfrecorderapi.BpfRecorderClient,
	profileToCollect *profileToCollect,
	profileNamespacedName types.NamespacedName,
	profileLabels map[string]string,
) (*seccompprofileapi.SeccompProfile, error) {
	response, err := r.SyscallsForProfile(
		ctx, recorderClient, &bpfrecorderapi.ProfileRequest{Name: profileToCollect.name},
	)
	if err != nil {
		// Recording was not found for this profile, this might be an init container
		// which is not longer active. Let's skip here and keep processing the
		// next profile.
		if grpcstatus.Convert(err).Message() == bpfrecorder.ErrNotFound.Error() {
			r.log.Error(err, "Recorded profile not found", "name", profileToCollect.name)

			return nil, errRecordedProfileNotFound
		}

		return nil, fmt.Errorf("getting syscalls for profile: %w", err)
	}

	arch, err := r.goArchToSeccompArch(response.GetGoArch())
	if err != nil {
		return nil, fmt.Errorf("getting seccomp arch: %w", err)
	}

	profileSpec := &seccompprofileapi.SeccompProfileSpec{
		DefaultAction: seccompprofileapi.ActErrno,
		Architectures: []seccompprofileapi.Arch{arch},
		Syscalls: []seccompprofileapi.Syscall{{
			Action: seccompprofileapi.ActAllow,
			Names:  response.GetSyscalls(),
		}},
	}

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      profileNamespacedName.Name,
			Namespace: profileNamespacedName.Namespace,
			Labels:    profileLabels,
		},
		Spec: *profileSpec,
	}

	return profile, nil
}

func (r *RecorderReconciler) collectApparmorBpfProfile(
	ctx context.Context,
	recorderClient bpfrecorderapi.BpfRecorderClient,
	profileToCollect *profileToCollect,
	profileNamespacedName types.NamespacedName,
	profileLabels map[string]string,
) (*apparmorprofileapi.AppArmorProfile, error) {
	response, err := r.ApparmorForProfile(
		ctx, recorderClient, &bpfrecorderapi.ProfileRequest{Name: profileToCollect.name},
	)
	if err != nil {
		// Recording was not found for this profile, this might be an init container
		// which is not longer active. Let's skip here and keep processing the
		// next profile.
		if grpcstatus.Convert(err).Message() == bpfrecorder.ErrNotFound.Error() {
			r.log.Error(err, "Recorded profile not found", "name", profileToCollect.name)

			return nil, errRecordedProfileNotFound
		}

		return nil, fmt.Errorf("getting syscalls for profile: %w", err)
	}

	spec := apparmorprofileapi.AppArmorProfileSpec{
		Abstract: r.generateAppArmorProfileAbstract(response),
	}

	profile := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      profileNamespacedName.Name,
			Namespace: profileNamespacedName.Namespace,
			Labels:    profileLabels,
		},
		Spec: spec,
	}

	return profile, nil
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

	target := &profileTarget{recordingName: parsed.profileName}
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

	if err := utils.UpdateResource(ctx, r.log, r.client, recording, recording.Kind); err != nil {
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
	err := retry.OnError(retry.DefaultRetry, func(err error) bool {
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

		if r.rejectedForGood(target.name.Name, err) {
			return fmt.Errorf("%w: %w", errProfileRejected, err)
		}

		return fmt.Errorf("create %s profile resource: %w", kind, err)
	}

	r.forbiddenAttempts.Delete(target.name.Name)

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

// maxForbiddenAttempts is how often storing a profile is tried when the API
// server forbids it, which can also be caused by a permission not granted yet.
const maxForbiddenAttempts = 5

// rejectedForGood reports whether the API server will reject the profile
// again, in which case retrying would only keep the recording going for good.
func (r *RecorderReconciler) rejectedForGood(name string, err error) bool {
	if kerrors.IsInvalid(err) || kerrors.IsRequestEntityTooLargeError(err) ||
		kerrors.IsBadRequest(err) {
		return true
	}

	if !kerrors.IsForbidden(err) {
		return false
	}

	value, _ := r.forbiddenAttempts.LoadOrStore(name, new(atomic.Int32))

	attempts, ok := value.(*atomic.Int32)
	if !ok || attempts.Add(1) >= maxForbiddenAttempts {
		r.forbiddenAttempts.Delete(name)

		return true
	}

	return false
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
func parseAnnotations(
	annotations map[string]string, kinds []annotationKind,
) (res []profileToCollect, err error) {
	for key, profile := range annotations {
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
	sb.keys = append(sb.keys, key)

	perms, ok := sb.permMap[key]
	if ok {
		perms.Insert(avc.GetPerm())
	} else {
		sb.permMap[key] = sets.New(avc.GetPerm())
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
