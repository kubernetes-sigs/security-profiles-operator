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

package profilerecorder

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"go.podman.io/common/pkg/seccomp"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	bpfrecorderapi "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	enricherapi "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	profilerecording1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	errInvalidAnnotation = "invalid Annotation"

	reasonProfileRecording      string = "ProfileRecording"
	reasonProfileCreated        string = "ProfileCreated"
	reasonProfileCreationFailed string = "CannotCreateProfile"
	reasonAnnotationParsing     string = "AnnotationParsing"

	seContextRequiredParts = 3
)

var errNameNotValid = errors.New(
	"recording name is not valid DNS1123 subdomain, check profileRecording events")
var errRecordedProfileNotFound = errors.New("recorded profile not found")

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
	record        record.EventRecorder
	nodeAddresses []string
	podsToWatch   sync.Map
}

type profileToCollect struct {
	kind profilerecording1alpha1.ProfileRecordingKind
	name string
}

type podToWatch struct {
	baseName types.NamespacedName
	recorder profilerecording1alpha1.ProfileRecorder
	profiles []profileToCollect
}

// Name returns the name of the controller.
func (r *RecorderReconciler) Name() string {
	return "recorder-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *RecorderReconciler) SchemeBuilder() *scheme.Builder {
	return profilerecording1alpha1.SchemeBuilder
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
	r.record = r.ManagerGetEventRecorderFor(mgr, name)

	return r.NewControllerManagedBy(
		mgr, name, r.isPodWithTraceAnnotation, r.isPodOnLocalNode, r,
	)
}

func (r *RecorderReconciler) getSPOD(ctx context.Context) (*spodv1alpha1.SecurityProfilesOperatorDaemon, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	return r.GetSPOD(ctx, r.client)
}

// Healthz is the liveness probe endpoint of the controller.
func (r *RecorderReconciler) Healthz(*http.Request) error {
	return nil
}

func (r *RecorderReconciler) isPodOnLocalNode(obj runtime.Object) bool {
	p, ok := obj.(*corev1.Pod)

	if !ok {
		return false
	}

	for _, addr := range r.nodeAddresses {
		if p.Status.HostIP == addr {
			return true
		}
	}

	return false
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

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
func (r *RecorderReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("pod", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	pod, err := r.GetPod(ctx, r.client, req.NamespacedName)
	if err != nil {
		if kerrors.IsNotFound(err) {
			collErr := r.collectProfile(ctx, req.NamespacedName)
			if errors.Is(collErr, errNameNotValid) {
				logger.Error(collErr, "cannot collect profile")
				// not reconcilable, no need to requeue
				return reconcile.Result{}, nil
			} else if collErr != nil {
				return reconcile.Result{}, fmt.Errorf("collect profile for removed pod: %w", collErr)
			}

			return reconcile.Result{}, nil
		}

		// Returning an error means we will be requeued implicitly.
		logger.Error(err, "Error reading pod")

		return reconcile.Result{}, fmt.Errorf("cannot get pod: %w", err)
	}

	if pod.Status.Phase == corev1.PodPending {
		if _, ok := r.podsToWatch.Load(req.String()); ok {
			// We're tracking this pod already
			return reconcile.Result{}, nil
		}

		logProfiles, err := parseLogAnnotations(pod.Annotations)
		if err != nil {
			// Malformed annotations could be set by users directly, which is
			// why we are ignoring them.
			logger.Info("Ignoring because unable to parse log annotation", "error", err)
			r.record.Event(pod, util.EventTypeWarning, reasonAnnotationParsing, err.Error())

			return reconcile.Result{}, nil
		}

		bpfProfiles, err := parseBpfAnnotations(pod.Annotations)
		if err != nil {
			// Malformed annotations could be set by users directly, which is
			// why we are ignoring them.
			logger.Info("Ignoring because unable to parse bpf annotation", "error", err)
			r.record.Event(pod, util.EventTypeWarning, reasonAnnotationParsing, err.Error())

			return reconcile.Result{}, nil
		}

		var (
			profiles []profileToCollect
			recorder profilerecording1alpha1.ProfileRecorder
		)

		//nolint:gocritic // should be intentionally no switch
		if len(logProfiles) > 0 {
			profiles = logProfiles
			recorder = profilerecording1alpha1.ProfileRecorderLogs
		} else if len(bpfProfiles) > 0 {
			if err := r.startBpfRecorder(ctx); err != nil {
				logger.Error(err, "unable to start bpf recorder")

				return reconcile.Result{}, err
			}

			profiles = bpfProfiles
			recorder = profilerecording1alpha1.ProfileRecorderBpf
		} else {
			logger.Info("No log or bpf annotations found on pod")

			return reconcile.Result{}, nil
		}

		for _, prf := range profiles {
			logger.Info("Recording profile", "kind", prf.kind, "name", prf.name, "pod", req.String())
		}

		// for pods managed by a replicated controller, let's store the replicated
		// name so that we can later strip the suffix from the fully-generated pod name
		baseName := req.NamespacedName
		if pod.GenerateName != "" {
			baseName.Name = pod.GenerateName
		}

		r.podsToWatch.Store(
			req.String(),
			podToWatch{baseName, recorder, profiles},
		)
		r.record.Event(pod, util.EventTypeNormal, reasonProfileRecording, "Recording profiles")
	}

	if pod.Status.Phase == corev1.PodSucceeded {
		collErr := r.collectProfile(ctx, req.NamespacedName)
		if errors.Is(collErr, errNameNotValid) {
			logger.Error(collErr, "cannot collect profile")
			// not reconcilable, no need to requeue
			return reconcile.Result{}, nil
		} else if collErr != nil {
			return reconcile.Result{}, fmt.Errorf("collect profile for succeeded pod: %w", collErr)
		}
	}

	return reconcile.Result{}, nil
}

func (r *RecorderReconciler) getBpfRecorderClient(
	ctx context.Context,
) (bpfrecorderapi.BpfRecorderClient, context.CancelFunc, error) {
	r.log.Info("Checking if bpf recorder is enabled")

	spod, err := r.getSPOD(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting SPOD config: %w", err)
	}

	enableBpfRecorderEnv, err := strconv.ParseBool(os.Getenv(config.EnableBpfRecorderEnvKey))
	if err != nil {
		enableBpfRecorderEnv = false
	}

	if !spod.Spec.EnableBpfRecorder && !enableBpfRecorderEnv {
		return nil, nil, errors.New("bpf recorder is not enabled")
	}

	r.log.Info("Connecting to local GRPC bpf recorder server")

	conn, cancel, err := r.DialBpfRecorder()
	if err != nil {
		return nil, nil, fmt.Errorf("connect to bpf recorder GRPC server: %w", err)
	}

	bpfRecorderClient := bpfrecorderapi.NewBpfRecorderClient(conn)

	return bpfRecorderClient, cancel, nil
}

func (r *RecorderReconciler) startBpfRecorder(ctx context.Context) error {
	recorderClient, cancel, err := r.getBpfRecorderClient(ctx)
	if err != nil {
		return fmt.Errorf("get bpf recorder client: %w", err)
	}
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	r.log.Info("Starting BPF recorder on node")

	return r.StartBpfRecorder(ctx, recorderClient)
}

func (r *RecorderReconciler) stopBpfRecorder(ctx context.Context) error {
	recorderClient, cancel1, err := r.getBpfRecorderClient(ctx)
	if err != nil {
		return fmt.Errorf("get bpf recorder client: %w", err)
	}
	defer cancel1()

	ctx, cancel2 := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel2()

	r.log.Info("Stopping BPF recorder on node")

	return r.StopBpfRecorder(ctx, recorderClient)
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
	if podToWatch.baseName.Name != podName.Name && strings.HasPrefix(podName.Name, podToWatch.baseName.Name) {
		// this is a replica, we need to strip the suffix from the pod name
		replicaSuffix = strings.TrimPrefix(podName.Name, podToWatch.baseName.Name)
	}

	if podToWatch.recorder == profilerecording1alpha1.ProfileRecorderLogs {
		if err := r.collectLogProfiles(
			ctx, replicaSuffix, podName, podToWatch.profiles,
		); err != nil {
			return fmt.Errorf("collect log profile: %w", err)
		}
	}

	if podToWatch.recorder == profilerecording1alpha1.ProfileRecorderBpf {
		if err := r.collectBpfProfiles(
			ctx, replicaSuffix, podName, podToWatch.profiles,
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

	if !spod.Spec.EnableLogEnricher && !enableLogEnricherEnv {
		return errors.New("log enricher not enabled")
	}

	r.log.Info("Connecting to local GRPC enricher server")

	conn, cancel, err := r.DialEnricher()
	if err != nil {
		return fmt.Errorf("connecting to local GRPC server: %w", err)
	}

	defer cancel()

	enricherClient := enricherapi.NewEnricherClient(conn)

	for _, prf := range profiles {
		parsedProfileAnnotation, err := parseProfileAnnotation(prf.name)
		if err != nil {
			return fmt.Errorf("parse profile raw annotation: %w", err)
		}

		profileNamespacedName := createProfileName(
			parsedProfileAnnotation.cntName, replicaSuffix,
			podName.Namespace, parsedProfileAnnotation.profileName)

		r.log.Info("Collecting profile", "name", profileNamespacedName, "kind", prf.kind)

		switch prf.kind {
		case profilerecording1alpha1.ProfileRecordingKindSeccompProfile:
			err = r.collectLogSeccompProfile(ctx, enricherClient, parsedProfileAnnotation, profileNamespacedName, prf.name)
		case profilerecording1alpha1.ProfileRecordingKindSelinuxProfile:
			err = r.collectLogSelinuxProfile(ctx, enricherClient, parsedProfileAnnotation, profileNamespacedName, prf.name)
		case profilerecording1alpha1.ProfileRecordingKindAppArmorProfile:
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

func (r *RecorderReconciler) collectLogSeccompProfile(
	ctx context.Context,
	enricherClient enricherapi.EnricherClient,
	parsedProfileName *parsedAnnotation,
	profileNamespacedName types.NamespacedName,
	profileID string,
) error {
	labels, err := profileLabels(
		ctx,
		r,
		parsedProfileName.profileName,
		parsedProfileName.cntName,
		profileNamespacedName.Namespace)
	if err != nil {
		return fmt.Errorf("creating profile labels: %w", err)
	}

	// Do this BEFORE reading the syscalls to hopefully minimize the
	// race window in case reading the syscalls failed. In that case we just reconcile
	// back here and loop through again
	err = r.setRecordingFinalizers(ctx, labels, parsedProfileName.profileName, profileNamespacedName.Namespace)
	if err != nil {
		return fmt.Errorf("setting finalizer on profilerecording: %w", err)
	}

	// Retrieve the syscalls for the recording
	request := &enricherapi.SyscallsRequest{Profile: profileID}

	response, err := r.Syscalls(ctx, enricherClient, request)
	if err != nil {
		if grpcstatus.Convert(err).Code() == grpccodes.NotFound &&
			grpcstatus.Convert(err).Message() == enricher.ErrorNoSyscalls {
			if err := r.ResetSyscalls(ctx, enricherClient, request); err != nil {
				return fmt.Errorf("reset syscalls for profile %s: %w", profileNamespacedName, err)
			}

			r.log.Info("No syscalls found, resetting profile", "profileID", profileID)

			return nil
		}

		return fmt.Errorf("retrieve syscalls for profile %s: %w", profileID, err)
	}

	arch, err := r.goArchToSeccompArch(response.GetGoArch())
	if err != nil {
		return fmt.Errorf("get seccomp arch: %w", err)
	}

	profileSpec := seccompprofileapi.SeccompProfileSpec{
		DefaultAction: seccomp.ActErrno,
		Architectures: []seccompprofileapi.Arch{arch},
		Syscalls: []*seccompprofileapi.Syscall{{
			Action: seccomp.ActAllow,
			Names:  response.GetSyscalls(),
		}},
	}

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      profileNamespacedName.Name,
			Namespace: profileNamespacedName.Namespace,
			Labels:    labels,
		},
		Spec: profileSpec,
	}

	if err := r.setDisabled(ctx, r.client,
		parsedProfileName.profileName, profileNamespacedName.Namespace,
		&profileSpec.SpecBase); err != nil {
		r.log.Error(err, "Cannot set the enabled flag")
		r.record.Event(profile, util.EventTypeWarning, reasonProfileCreationFailed, err.Error())

		return fmt.Errorf("format selinuxprofile resource: %w", err)
	}

	res, err := r.CreateOrUpdate(ctx, r.client, profile,
		func() error {
			profile.Spec = profileSpec

			return nil
		},
	)
	if err != nil {
		r.log.Error(err, "Cannot create seccompprofile resource")
		r.record.Event(profile, util.EventTypeWarning, reasonProfileCreationFailed, err.Error())

		return fmt.Errorf("create seccompProfile resource: %w", err)
	}

	r.log.Info("Created/updated profile", "action", res, "name", profileNamespacedName.Name)
	r.record.Event(profile, util.EventTypeNormal, reasonProfileCreated, "seccomp profile created")

	// Reset the syscalls for further recordings
	if err := r.ResetSyscalls(ctx, enricherClient, request); err != nil {
		return fmt.Errorf("reset syscalls for profile %s: %w", profileID, err)
	}

	return nil
}

func (r *RecorderReconciler) collectLogSelinuxProfile(
	ctx context.Context,
	enricherClient enricherapi.EnricherClient,
	parsedProfileName *parsedAnnotation,
	profileNamespacedName types.NamespacedName,
	profileID string,
) error {
	labels, err := profileLabels(
		ctx,
		r,
		parsedProfileName.profileName,
		parsedProfileName.cntName,
		profileNamespacedName.Namespace)
	if err != nil {
		return fmt.Errorf("creating profile labels: %w", err)
	}

	// Do this BEFORE reading the AVCs to hopefully minimize the
	// race window in case reading the AVCs failed. In that case we just reconcile
	// back here and loop through again
	err = r.setRecordingFinalizers(ctx, labels, parsedProfileName.profileName, profileNamespacedName.Namespace)
	if err != nil {
		return fmt.Errorf("setting finalizer on profilerecording: %w", err)
	}

	// Retrieve the AVCs for the recording
	request := &enricherapi.AvcRequest{Profile: profileID}

	response, err := r.Avcs(ctx, enricherClient, request)
	if err != nil {
		if grpcstatus.Convert(err).Code() == grpccodes.NotFound &&
			grpcstatus.Convert(err).Message() == enricher.ErrorNoAvcs {
			if err := r.ResetAvcs(ctx, enricherClient, request); err != nil {
				return fmt.Errorf("reset selinuxprofile for profile %s: %w", profileNamespacedName, err)
			}

			r.log.Info("No AVCs found, resetting profile", "profileID", profileID)

			return nil
		}

		return fmt.Errorf("retrieve avcs for profile %s: %w", profileID, err)
	}

	selinuxProfileSpec := selxv1alpha2.SelinuxProfileSpec{
		Inherit: []selxv1alpha2.PolicyRef{
			{
				Kind: selxv1alpha2.SystemPolicyKind,
				Name: "container",
			},
		},
	}

	profile := &selxv1alpha2.SelinuxProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      profileNamespacedName.Name,
			Namespace: profileNamespacedName.Namespace,
			Labels:    labels,
		},
		Spec: selinuxProfileSpec,
	}

	selinuxProfileSpec.Allow, err = r.formatSelinuxProfile(profile, response)
	if err != nil {
		r.log.Error(err, "Cannot format selinuxprofile")
		r.record.Event(profile, util.EventTypeWarning, reasonProfileCreationFailed, err.Error())

		return fmt.Errorf("format selinuxprofile resource: %w", err)
	}

	r.log.Info("Created", "profile", profile)

	if err := r.setDisabled(ctx, r.client,
		parsedProfileName.profileName, profileNamespacedName.Namespace,
		&selinuxProfileSpec.SpecBase); err != nil {
		r.log.Error(err, "Cannot set the enabled flag")
		r.record.Event(profile, util.EventTypeWarning, reasonProfileCreationFailed, err.Error())

		return fmt.Errorf("format selinuxprofile resource: %w", err)
	}

	res, err := r.CreateOrUpdate(ctx, r.client, profile,
		func() error {
			profile.Spec = selinuxProfileSpec

			return nil
		},
	)
	if err != nil {
		r.log.Error(err, "Cannot create selinuxprofile resource")
		r.record.Event(profile, util.EventTypeWarning, reasonProfileCreationFailed, err.Error())

		return fmt.Errorf("create selinuxprofile resource: %w", err)
	}

	r.log.Info("Created/updated selinux profile", "action", res, "name", profileNamespacedName)
	r.record.Event(profile, util.EventTypeNormal, reasonProfileCreated, "selinuxprofile profile created")

	// Reset the selinuxprofile for further recordings
	if err := r.ResetAvcs(ctx, enricherClient, request); err != nil {
		return fmt.Errorf("reset selinuxprofile for profile %s: %w", profileNamespacedName, err)
	}

	return nil
}

func (r *RecorderReconciler) formatSelinuxProfile(
	selinuxprofile *selxv1alpha2.SelinuxProfile,
	avcResponse *enricherapi.AvcResponse,
) (selxv1alpha2.Allow, error) {
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
) error {
	recorderClient, cancel, err := r.getBpfRecorderClient(ctx)
	if err != nil {
		return fmt.Errorf("get bpf recorder client: %w", err)
	}
	defer cancel()

	for _, profileToCollect := range profiles {
		ptc := profileToCollect

		parsedProfileName, err := parseProfileAnnotation(profileToCollect.name)
		if err != nil {
			return fmt.Errorf("parse profile raw annotation: %w", err)
		}

		profileNamespacedName := createProfileName(
			parsedProfileName.cntName, replicaSuffix,
			podName.Namespace, parsedProfileName.profileName)

		labels, err := profileLabels(
			ctx,
			r,
			parsedProfileName.profileName,
			parsedProfileName.cntName,
			profileNamespacedName.Namespace)
		if err != nil {
			return fmt.Errorf("creating profile labels: %w", err)
		}

		// Do this BEFORE reading the syscalls to hopefully minimize the
		// race window in case reading the syscalls failed. In that case we just reconcile
		// back here and loop through again
		err = r.setRecordingFinalizers(ctx, labels, parsedProfileName.profileName, profileNamespacedName.Namespace)
		if err != nil {
			return fmt.Errorf("setting finalizer on profilerecording: %w", err)
		}

		r.log.Info("Collecting BPF profile", "name", profileToCollect.name, "kind", profileToCollect.kind)

		switch profileToCollect.kind {
		case profilerecording1alpha1.ProfileRecordingKindSeccompProfile:
			seccompProfile, err := r.collectSeccompBpfProfile(ctx, recorderClient, &ptc, profileNamespacedName, labels)
			if err != nil {
				// skip empty profiles
				if errors.Is(err, errRecordedProfileNotFound) {
					continue
				}

				return fmt.Errorf("collecting seccomp profile %s: %w", profileToCollect.name, err)
			}

			err = r.updateOrCreateSeccompResource(
				ctx, parsedProfileName.profileName, profileNamespacedName.Namespace, seccompProfile)
			if err != nil {
				return fmt.Errorf("creating/updating seccomp profile %s: %w", profileToCollect.name, err)
			}
		case profilerecording1alpha1.ProfileRecordingKindAppArmorProfile:
			apparmorProfile, err := r.collectApparmorBpfProfile(ctx, recorderClient, &ptc, profileNamespacedName, labels)
			if err != nil {
				// skip empty profiles
				if errors.Is(err, errRecordedProfileNotFound) {
					continue
				}

				return fmt.Errorf("collecting apparmor profile %s: %w", profileToCollect.name, err)
			}

			err = r.updateOrCreateApparmorResource(
				ctx, parsedProfileName.profileName, profileNamespacedName.Namespace, apparmorProfile)
			if err != nil {
				return fmt.Errorf("creating/updating apparmor profile %s: %w", profileToCollect.name, err)
			}
		case profilerecording1alpha1.ProfileRecordingKindSelinuxProfile:
			r.log.Info("Profile kind not supported by BPF recoder", "name", profileToCollect.name, "kind", profileToCollect.kind)

			continue
		}
	}

	if err := r.stopBpfRecorder(ctx); err != nil {
		r.log.Error(err, "Unable to stop bpf recorder")

		return fmt.Errorf("stop bpf recorder: %w", err)
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

	profileSpec := seccompprofileapi.SeccompProfileSpec{
		DefaultAction: seccomp.ActErrno,
		Architectures: []seccompprofileapi.Arch{arch},
		Syscalls: []*seccompprofileapi.Syscall{{
			Action: seccomp.ActAllow,
			Names:  response.GetSyscalls(),
		}},
	}

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      profileNamespacedName.Name,
			Namespace: profileNamespacedName.Namespace,
			Labels:    profileLabels,
		},
		Spec: profileSpec,
	}

	return profile, nil
}

//nolint:dupl // This requires a specific profile type which prevents the reducton of duplicated code
func (r *RecorderReconciler) updateOrCreateSeccompResource(
	ctx context.Context,
	profileRecordingName string,
	profileNamespace string,
	profile *seccompprofileapi.SeccompProfile,
) error {
	if err := r.setDisabled(ctx, r.client,
		profileRecordingName, profileNamespace,
		&profile.Spec.SpecBase); err != nil {
		r.log.Error(err, "Cannot set the disable flag on profile",
			"name", profileRecordingName,
			"namespace", profileNamespace,
		)
		r.record.Event(profile, util.EventTypeWarning, reasonProfileCreationFailed, err.Error())

		return fmt.Errorf("disabling profile after recording: %w", err)
	}

	profileSpec := profile.Spec

	res, err := r.CreateOrUpdate(ctx, r.client, profile,
		func() error {
			profile.Spec = profileSpec

			return nil
		},
	)
	if err != nil {
		r.log.Error(err, "Cannot create profile resource")
		r.record.Event(profile, util.EventTypeWarning, reasonProfileCreationFailed, err.Error())

		return fmt.Errorf("creating profile resource: %w", err)
	}

	r.log.Info("Created/updated profile", "action", res, "name", profileNamespace)
	r.record.Event(profile, util.EventTypeNormal, reasonProfileCreated, "seccomp profile created")

	return nil
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
	abstract := apparmorprofileapi.AppArmorAbstract{}
	enabled := true

	if len(response.GetFiles().GetAllowedExecutables()) != 0 || len(response.GetFiles().GetAllowedLibraries()) != 0 {
		abstract.Executable = &apparmorprofileapi.AppArmorExecutablesRules{}

		if len(response.GetFiles().GetAllowedExecutables()) != 0 {
			sort.Strings(response.GetFiles().GetAllowedExecutables())
			ExecutableAllowedExecCopy := make([]string, len(response.GetFiles().GetAllowedExecutables()))
			copy(ExecutableAllowedExecCopy, response.GetFiles().GetAllowedExecutables())
			abstract.Executable.AllowedExecutables = &ExecutableAllowedExecCopy
		}

		if len(response.GetFiles().GetAllowedLibraries()) != 0 {
			sort.Strings(response.GetFiles().GetAllowedLibraries())
			ExecutableAllowedLibCopy := make([]string, len(response.GetFiles().GetAllowedLibraries()))
			copy(ExecutableAllowedLibCopy, response.GetFiles().GetAllowedLibraries())
			abstract.Executable.AllowedLibraries = &ExecutableAllowedLibCopy
		}
	}

	if (len(response.GetFiles().GetReadonlyPaths()) != 0) ||
		(len(response.GetFiles().GetWriteonlyPaths()) != 0) ||
		(len(response.GetFiles().GetReadwritePaths()) != 0) {
		files := apparmorprofileapi.AppArmorFsRules{}

		if len(response.GetFiles().GetReadonlyPaths()) != 0 {
			sort.Strings(response.GetFiles().GetReadonlyPaths())
			FileReadOnlyCopy := make([]string, len(response.GetFiles().GetReadonlyPaths()))
			copy(FileReadOnlyCopy, response.GetFiles().GetReadonlyPaths())
			files.ReadOnlyPaths = &FileReadOnlyCopy
		}

		if len(response.GetFiles().GetWriteonlyPaths()) != 0 {
			sort.Strings(response.GetFiles().GetWriteonlyPaths())
			FileWriteOnlyCopy := make([]string, len(response.GetFiles().GetWriteonlyPaths()))
			copy(FileWriteOnlyCopy, response.GetFiles().GetWriteonlyPaths())
			files.WriteOnlyPaths = &FileWriteOnlyCopy
		}

		if len(response.GetFiles().GetReadwritePaths()) != 0 {
			sort.Strings(response.GetFiles().GetReadwritePaths())
			FileReadWriteCopy := make([]string, len(response.GetFiles().GetReadwritePaths()))
			copy(FileReadWriteCopy, response.GetFiles().GetReadwritePaths())
			files.ReadWritePaths = &FileReadWriteCopy
		}

		abstract.Filesystem = &files
	}

	if response.GetSocket().GetUseRaw() || response.GetSocket().GetUseTcp() || response.GetSocket().GetUseUdp() {
		net := apparmorprofileapi.AppArmorNetworkRules{}
		proto := apparmorprofileapi.AppArmorAllowedProtocols{}

		if response.GetSocket().GetUseRaw() {
			net.AllowRaw = &enabled
		}

		if response.GetSocket().GetUseTcp() {
			proto.AllowTCP = &enabled
			net.Protocols = &proto
		}

		if response.GetSocket().GetUseTcp() {
			proto.AllowUDP = &enabled
			net.Protocols = &proto
		}

		abstract.Network = &net
	}

	if len(response.GetCapabilities()) != 0 {
		capabilities := apparmorprofileapi.AppArmorCapabilityRules{}
		capabilities.AllowedCapabilities = response.GetCapabilities()
		abstract.Capability = &capabilities
	}

	return abstract
}

//nolint:dupl // This requires a specific profile type which prevents the reducton of duplicated code
func (r *RecorderReconciler) updateOrCreateApparmorResource(
	ctx context.Context,
	profileRecordingName string,
	profileNamespace string,
	profile *apparmorprofileapi.AppArmorProfile,
) error {
	if err := r.setDisabled(ctx, r.client,
		profileRecordingName, profileNamespace,
		&profile.Spec.SpecBase); err != nil {
		r.log.Error(err, "Cannot set the disable flag on profile",
			"name", profileRecordingName,
			"namespace", profileNamespace,
		)
		r.record.Event(profile, util.EventTypeWarning, reasonProfileCreationFailed, err.Error())

		return fmt.Errorf("disabling profile after recording: %w", err)
	}

	profileSpec := profile.Spec

	res, err := r.CreateOrUpdate(ctx, r.client, profile,
		func() error {
			profile.Spec = profileSpec

			return nil
		},
	)
	if err != nil {
		r.log.Error(err, "Cannot create profile resource")
		r.record.Event(profile, util.EventTypeWarning, reasonProfileCreationFailed, err.Error())

		return fmt.Errorf("creating profile resource: %w", err)
	}

	r.log.Info("Created/updated profile", "action", res, "name", profileNamespace)
	r.record.Event(profile, util.EventTypeNormal, reasonProfileCreated, "apparmor profile created")

	return nil
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
			fmt.Errorf("invalid annotation: %s, expected %d parts got %d", annotation, expectedParts, len(parts))
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

// parseLogAnnotations parses the provided annotations and extracts the
// mandatory output profiles for the log recorder.
func parseLogAnnotations(annotations map[string]string) (res []profileToCollect, err error) {
	for key, profile := range annotations {
		var collectProfile profileToCollect

		//nolint:gocritic
		if strings.HasPrefix(key, config.SeccompProfileRecordLogsAnnotationKey) {
			collectProfile.kind = profilerecording1alpha1.ProfileRecordingKindSeccompProfile
		} else if strings.HasPrefix(key, config.SelinuxProfileRecordLogsAnnotationKey) {
			collectProfile.kind = profilerecording1alpha1.ProfileRecordingKindSelinuxProfile
		} else {
			continue
		}

		if profile == "" {
			return nil, fmt.Errorf(
				"%s: providing output profile is mandatory",
				errInvalidAnnotation,
			)
		}

		collectProfile.name = profile

		res = append(res, collectProfile)
	}

	return res, nil
}

// parseBpfAnnotations parses the provided annotations and extracts the
// mandatory output profiles for the bpf recorder.
func parseBpfAnnotations(annotations map[string]string) (res []profileToCollect, err error) {
	for key, profile := range annotations {
		var collectProfile profileToCollect

		//nolint:gocritic
		if strings.HasPrefix(key, config.SeccompProfileRecordBpfAnnotationKey) {
			collectProfile.kind = profilerecording1alpha1.ProfileRecordingKindSeccompProfile
		} else if strings.HasPrefix(key, config.ApparmorProfileRecordBpfAnnotationKey) {
			collectProfile.kind = profilerecording1alpha1.ProfileRecordingKindAppArmorProfile
		} else {
			continue
		}

		if profile == "" {
			return nil, fmt.Errorf(
				"%s: providing output profile is mandatory",
				errInvalidAnnotation,
			)
		}

		collectProfile.name = profile

		res = append(res, collectProfile)
	}

	return res, nil
}

type seProfileBuilder struct {
	permMap       map[string]sets.Set[string]
	usageCtx      string
	policyBuilder selxv1alpha2.Allow
	log           logr.Logger
	// used to optimize sorting
	keys []string
}

func newSeProfileBuilder(usageCtx string, log logr.Logger) *seProfileBuilder {
	return &seProfileBuilder{
		permMap:       make(map[string]sets.Set[string]),
		usageCtx:      usageCtx,
		policyBuilder: make(selxv1alpha2.Allow),
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

func (sb *seProfileBuilder) Format() (selxv1alpha2.Allow, error) {
	sort.Strings(sb.keys)

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
	_, haveType := sb.policyBuilder[selxv1alpha2.LabelKey(setype)]
	if !haveType {
		sb.policyBuilder[selxv1alpha2.LabelKey(setype)] = make(map[selxv1alpha2.ObjectClassKey]selxv1alpha2.PermissionSet)
	}

	typePerms := sb.policyBuilder[selxv1alpha2.LabelKey(setype)]
	l := val.UnsortedList()
	sort.Strings(l)
	typePerms[selxv1alpha2.ObjectClassKey(tclass)] = selxv1alpha2.PermissionSet(l)

	return nil
}

func (sb *seProfileBuilder) targetClassCtx(key string) (tclass, tcontext string) {
	splitkey := strings.Split(key, " ")
	tclass = splitkey[0]

	tcontext = splitkey[1]
	if tcontext == config.SelinuxPermissiveProfile {
		// rewrite the context to reference itself.
		// We replace this when writing the policy.
		tcontext = selxv1alpha2.AllowSelf
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

func profilePartial(
	ctx context.Context, r *RecorderReconciler, profileName, namespace string,
) (bool, error) {
	recorder := profilerecording1alpha1.ProfileRecording{}

	err := r.ClientGet(
		ctx, r.client, client.ObjectKey{Name: profileName, Namespace: namespace}, &recorder)
	if kerrors.IsNotFound(err) {
		// in case the recording disappeared, we consider the profiles ready and let
		// the admin deal with them
		return true, err
	} else if err != nil {
		return false, err
	}

	var profilePartial bool

	switch recorder.Spec.MergeStrategy {
	case profilerecording1alpha1.ProfileMergeNone:
		profilePartial = false
	case profilerecording1alpha1.ProfileMergeContainers:
		profilePartial = true
	}

	return profilePartial, nil
}

func profileLabels(
	ctx context.Context, r *RecorderReconciler, recordingName, cntName, namespace string,
) (map[string]string, error) {
	errs := validation.IsDNS1123Label(recordingName)
	if len(errs) > 0 {
		return nil, errNameNotValid
	}

	labels := map[string]string{
		profilerecording1alpha1.ProfileToRecordingLabel: recordingName,
		profilerecording1alpha1.ProfileToContainerLabel: cntName,
	}

	partial, err := profilePartial(ctx, r, recordingName, namespace)
	if err != nil {
		return nil, err
	}

	if partial {
		labels[profilebase.ProfilePartialLabel] = "true"
	}

	return labels, nil
}

func (r *RecorderReconciler) setDisabled(
	ctx context.Context,
	cli client.Client,
	profileRecordingName, namespace string,
	profileSpecBase *profilebase.SpecBase,
) error {
	recording, err := r.GetRecording(ctx, cli, types.NamespacedName{Name: profileRecordingName, Namespace: namespace})
	if err != nil {
		return fmt.Errorf("get recording: %w", err)
	}

	profileSpecBase.Disabled = recording.Spec.DisableProfileAfterRecording

	return nil
}

func (r *RecorderReconciler) setRecordingFinalizers(
	ctx context.Context,
	labels map[string]string,
	profileRecordingName, namespace string,
) error {
	_, ok := labels[profilebase.ProfilePartialLabel]
	if !ok {
		return nil
	}

	recording := profilerecording1alpha1.ProfileRecording{}
	if err := r.client.Get(
		ctx,
		types.NamespacedName{
			Name:      profileRecordingName,
			Namespace: namespace,
		},
		&recording); err != nil {
		return fmt.Errorf("get recording: %w", err)
	}

	if !controllerutil.ContainsFinalizer(&recording, profilerecording1alpha1.RecordingHasUnmergedProfiles) {
		controllerutil.AddFinalizer(&recording, profilerecording1alpha1.RecordingHasUnmergedProfiles)
	}

	if err := utils.UpdateResource(ctx, r.log, r.client, &recording, recording.Kind); err != nil {
		return fmt.Errorf("update recording: %w", err)
	}

	return nil
}
