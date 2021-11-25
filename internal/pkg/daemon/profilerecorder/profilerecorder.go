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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/containers/common/pkg/seccomp"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	bpfrecorderapi "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	enricherapi "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	profilerecording1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	errGetClient         = "cannot get client connection"
	errGetNode           = "cannot get node object"
	errGetPod            = "cannot get pod"
	errInvalidAnnotation = "invalid Annotation"

	reasonProfileRecording      event.Reason = "SeccompProfileRecording"
	reasonProfileCreated        event.Reason = "SeccompProfileCreated"
	reasonProfileCreationFailed event.Reason = "CannotCreateSeccompProfile"
	reasonAnnotationParsing     event.Reason = "SeccompAnnotationParsing"

	seContextRequiredParts = 3
)

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
	record        event.Recorder
	nodeAddresses []string
	podsToWatch   sync.Map
}

type profileToCollect struct {
	kind profilerecording1alpha1.ProfileRecordingKind
	name string
}

type podToWatch struct {
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

// nolint: lll
//
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch

// Setup is the initialization of the controller.
func (r *RecorderReconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	const name = "profilerecorder"
	c, err := r.NewClient(mgr)
	if err != nil {
		return errors.Wrap(err, errGetClient)
	}

	node := &corev1.Node{}
	if err := r.ClientGet(
		c, client.ObjectKey{Name: os.Getenv(config.NodeNameEnvKey)}, node,
	); err != nil {
		return errors.Wrap(err, errGetNode)
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
		return errors.New("Unable to get node's internal Address")
	}

	r.client = r.ManagerGetClient(mgr)
	r.nodeAddresses = nodeAddresses
	r.record = event.NewAPIRecorder(r.ManagerGetEventRecorderFor(mgr, name))

	return r.NewControllerManagedBy(
		mgr, name, r.isPodWithTraceAnnotation, r.isPodOnLocalNode, r,
	)
}

func (r *RecorderReconciler) getSPOD() (*spodv1alpha1.SecurityProfilesOperatorDaemon, error) {
	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	return common.GetSPOD(ctx, r.client)
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
		if strings.HasPrefix(key, config.SeccompProfileRecordHookAnnotationKey) ||
			strings.HasPrefix(key, config.SelinuxProfileRecordLogsAnnotationKey) ||
			strings.HasPrefix(key, config.SeccompProfileRecordLogsAnnotationKey) ||
			strings.HasPrefix(key, config.SeccompProfileRecordBpfAnnotationKey) {
			return true
		}
	}

	return false
}

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
func (r *RecorderReconciler) Reconcile(_ context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("pod", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	pod := &corev1.Pod{}
	if err := r.client.Get(ctx, req.NamespacedName, pod); err != nil {
		if kerrors.IsNotFound(err) {
			if err := r.collectProfile(ctx, req.NamespacedName); err != nil {
				return reconcile.Result{}, errors.Wrap(err, "collect profile for removed pod")
			}
		} else {
			// Returning an error means we will be requeued implicitly.
			logger.Error(err, "Error reading pod")
			return reconcile.Result{}, errors.Wrap(err, errGetPod)
		}
	}

	if pod.Status.Phase == corev1.PodPending {
		if _, ok := r.podsToWatch.Load(req.NamespacedName.String()); ok {
			// We're tracking this pod already
			return reconcile.Result{}, nil
		}

		hookProfiles, err := parseHookAnnotations(pod.Annotations)
		if err != nil {
			// Malformed annotations could be set by users directly, which is
			// why we are ignoring them.
			logger.Info("Ignoring because unable to parse hook annotation", "error", err)
			r.record.Event(pod, event.Warning(reasonAnnotationParsing, err))
			return reconcile.Result{}, nil
		}

		logProfiles, err := parseLogAnnotations(pod.Annotations)
		if err != nil {
			// Malformed annotations could be set by users directly, which is
			// why we are ignoring them.
			logger.Info("Ignoring because unable to parse log annotation", "error", err)
			r.record.Event(pod, event.Warning(reasonAnnotationParsing, err))
			return reconcile.Result{}, nil
		}

		bpfProfiles, err := parseBpfAnnotations(pod.Annotations)
		if err != nil {
			// Malformed annotations could be set by users directly, which is
			// why we are ignoring them.
			logger.Info("Ignoring because unable to parse bpf annotation", "error", err)
			r.record.Event(pod, event.Warning(reasonAnnotationParsing, err))
			return reconcile.Result{}, nil
		}

		var profiles []profileToCollect
		var recorder profilerecording1alpha1.ProfileRecorder
		if len(hookProfiles) > 0 { // nolint: gocritic
			profiles = hookProfiles
			recorder = profilerecording1alpha1.ProfileRecorderHook
		} else if len(logProfiles) > 0 {
			profiles = logProfiles
			recorder = profilerecording1alpha1.ProfileRecorderLogs
		} else if len(bpfProfiles) > 0 {
			if err := r.startBpfRecorder(); err != nil {
				logger.Error(err, "unable to start bpf recorder")
				return reconcile.Result{}, nil
			}
			profiles = bpfProfiles
			recorder = profilerecording1alpha1.ProfileRecorderBpf
		} else {
			logger.Info("Neither hook nor log annotations found on pod")
			return reconcile.Result{}, nil
		}

		for _, prf := range profiles {
			logger.Info("Recording profile", "kind", prf.kind, "name", prf.name, "pod", req.NamespacedName.String())
		}

		r.podsToWatch.Store(
			req.NamespacedName.String(),
			podToWatch{recorder, profiles},
		)
		r.record.Event(pod, event.Normal(reasonProfileRecording, "Recording profiles"))
	}

	if pod.Status.Phase == corev1.PodSucceeded {
		if err := r.collectProfile(ctx, req.NamespacedName); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "collect profile for succeeded pod")
		}
	}

	return reconcile.Result{}, nil
}

func (r *RecorderReconciler) getBpfRecorderClient() (bpfrecorderapi.BpfRecorderClient, context.CancelFunc, error) {
	r.log.Info("Checking if bpf recorder is enabled")

	spod, err := r.getSPOD()
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting SPOD config")
	}

	if !spod.Spec.EnableBpfRecorder {
		return nil, nil, errors.New("bpf recorder is not enabled")
	}

	r.log.Info("Connecting to local GRPC bpf recorder server")
	conn, cancel, err := bpfrecorder.Dial()
	if err != nil {
		return nil, nil, errors.Wrap(err, "connect to bpf recorder GRPC server")
	}
	enricherClient := bpfrecorderapi.NewBpfRecorderClient(conn)

	return enricherClient, cancel, nil
}

func (r *RecorderReconciler) startBpfRecorder() error {
	recorderClient, cancel, err := r.getBpfRecorderClient()
	if err != nil {
		return errors.Wrap(err, "get bpf recorder client")
	}
	defer cancel()

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()
	r.log.Info("Starting BPF recorder on node")
	_, err = recorderClient.Start(ctx, &bpfrecorderapi.EmptyRequest{})
	return err
}

func (r *RecorderReconciler) stopBpfRecorder() error {
	recorderClient, cancel, err := r.getBpfRecorderClient()
	if err != nil {
		return errors.Wrap(err, "get bpf recorder client")
	}
	defer cancel()

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()
	r.log.Info("Stopping BPF recorder on node")
	_, err = recorderClient.Stop(ctx, &bpfrecorderapi.EmptyRequest{})
	return err
}

func (r *RecorderReconciler) collectProfile(
	ctx context.Context, name types.NamespacedName,
) error {
	n := name.String()

	value, ok := r.podsToWatch.Load(n)
	if !ok {
		return nil
	}

	podToWatch, ok := value.(podToWatch)
	if !ok {
		return errors.New("type assert pod to watch")
	}

	if podToWatch.recorder == profilerecording1alpha1.ProfileRecorderHook {
		if err := r.collectLocalProfiles(
			ctx, name, podToWatch.profiles,
		); err != nil {
			return errors.Wrap(err, "collect local profile")
		}
	}

	if podToWatch.recorder == profilerecording1alpha1.ProfileRecorderLogs {
		if err := r.collectLogProfiles(
			ctx, name, podToWatch.profiles,
		); err != nil {
			return errors.Wrap(err, "collect log profile")
		}
	}

	if podToWatch.recorder == profilerecording1alpha1.ProfileRecorderBpf {
		if err := r.collectBpfProfiles(
			ctx, name, podToWatch.profiles,
		); err != nil {
			return errors.Wrap(err, "collect bpf profile")
		}
	}

	r.podsToWatch.Delete(n)
	return nil
}

func (r *RecorderReconciler) collectLocalProfiles(
	ctx context.Context,
	name types.NamespacedName,
	profiles []profileToCollect,
) error {
	for _, prf := range profiles {
		profilePath := prf.name
		if prf.kind != profilerecording1alpha1.ProfileRecordingKindSeccompProfile {
			return errors.New("only seccomp profiles supported via a hook")
		}

		r.log.Info("Collecting profile", "path", profilePath)

		data, err := ioutil.ReadFile(profilePath)
		if err != nil {
			r.log.Error(err, "Failed to read profile")
			return errors.Wrap(err, "read profile")
		}

		// Remove the file extension and timestamp
		profileName, err := extractProfileName(filepath.Base(profilePath))
		if err != nil {
			return errors.Wrap(err, "extract profile name")
		}

		profile := &seccompprofileapi.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      profileName,
				Namespace: name.Namespace,
			},
		}
		res, err := controllerutil.CreateOrUpdate(ctx, r.client, profile,
			func() error {
				return errors.Wrap(
					json.Unmarshal(data, &profile.Spec),
					"unmarshal profile spec JSON",
				)
			},
		)
		if err != nil {
			r.log.Error(err, "Cannot create seccompprofile resource")
			r.record.Event(profile, event.Warning(reasonProfileCreationFailed, err))
			return errors.Wrap(err, "create seccompProfile resource")
		}
		r.log.Info("Created/updated profile", "action", res, "name", profileName)
		r.record.Event(
			profile,
			event.Normal(reasonProfileCreated, "seccomp profile created"),
		)
	}

	return nil
}

func (r *RecorderReconciler) collectLogProfiles(
	ctx context.Context,
	name types.NamespacedName,
	profiles []profileToCollect,
) error {
	r.log.Info("Checking checking if enricher is enabled")

	spod, err := r.getSPOD()
	if err != nil {
		return errors.Wrap(err, "getting SPOD config")
	}

	if !spod.Spec.EnableLogEnricher {
		return errors.New("log enricher not enabled")
	}

	r.log.Info("Connecting to local GRPC enricher server")
	conn, cancel, err := enricher.Dial()
	if err != nil {
		return errors.Wrap(err, "connecting to local GRPC server")
	}
	defer cancel()
	enricherClient := enricherapi.NewEnricherClient(conn)

	for _, prf := range profiles {
		// Remove the timestamp
		profileName, err := extractProfileName(prf.name)
		if err != nil {
			return errors.Wrap(err, "extract profile name")
		}

		r.log.Info("Collecting profile", "name", profileName, "kind", prf.kind)

		switch prf.kind {
		case profilerecording1alpha1.ProfileRecordingKindSeccompProfile:
			err = r.collectLogSeccompProfile(ctx, enricherClient, profileName, name.Namespace, prf.name)
		case profilerecording1alpha1.ProfileRecordingKindSelinuxProfile:
			err = r.collectLogSelinuxProfile(ctx, enricherClient, profileName, name.Namespace, prf.name)
		default:
			err = errors.Errorf("unrecognized kind %s", prf.kind)
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
	profileName string,
	namespace string,
	profileID string,
) error {
	// Retrieve the syscalls for the recording
	request := &enricherapi.SyscallsRequest{Profile: profileID}
	response, err := enricherClient.Syscalls(ctx, request)
	if err != nil {
		return errors.Wrapf(
			err, "retrieve syscalls for profile %s", profileID,
		)
	}

	arch, err := goArchToSeccompArch(response.GoArch)
	if err != nil {
		return errors.Wrap(err, "get seccomp arch")
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
			Name:      profileName,
			Namespace: namespace,
		},
		Spec: profileSpec,
	}

	res, err := controllerutil.CreateOrUpdate(ctx, r.client, profile,
		func() error {
			profile.Spec = profileSpec
			return nil
		},
	)
	if err != nil {
		r.log.Error(err, "Cannot create seccompprofile resource")
		r.record.Event(profile, event.Warning(reasonProfileCreationFailed, err))
		return errors.Wrap(err, "create seccompProfile resource")
	}

	r.log.Info("Created/updated profile", "action", res, "name", profileName)
	r.record.Event(
		profile,
		event.Normal(reasonProfileCreated, "seccomp profile created"),
	)

	// Reset the syscalls for further recordings
	if _, err := enricherClient.ResetSyscalls(ctx, request); err != nil {
		return errors.Wrapf(
			err, "reset syscalls for profile %s", profileID,
		)
	}

	return nil
}

func (r *RecorderReconciler) collectLogSelinuxProfile(
	ctx context.Context,
	enricherClient enricherapi.EnricherClient,
	profileName string,
	namespace string,
	profileID string,
) error {
	// Retrieve the syscalls for the recording
	request := &enricherapi.AvcRequest{Profile: profileID}
	response, err := enricherClient.Avcs(ctx, request)
	if err != nil {
		return errors.Wrapf(
			err, "retrieve avcs for profile %s", profileID,
		)
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
			Name:      profileName,
			Namespace: namespace,
		},
		Spec: selinuxProfileSpec,
	}

	selinuxProfileSpec.Allow, err = r.formatSelinuxProfile(profile, response)
	if err != nil {
		r.log.Error(err, "Cannot format selinuxprofile")
		r.record.Event(profile, event.Warning(reasonProfileCreationFailed, err))
		return errors.Wrap(err, "format selinuxprofile resource")
	}
	r.log.Info("Created", "profile", profile)

	res, err := controllerutil.CreateOrUpdate(ctx, r.client, profile,
		func() error {
			profile.Spec = selinuxProfileSpec
			return nil
		},
	)
	if err != nil {
		r.log.Error(err, "Cannot create selinuxprofile resource")
		r.record.Event(profile, event.Warning(reasonProfileCreationFailed, err))
		return errors.Wrap(err, "create selinuxprofile resource")
	}
	r.log.Info("Created/updated selinux profile", "action", res, "name", profileName)
	r.record.Event(
		profile,
		event.Normal(reasonProfileCreated, "selinuxprofile profile created"),
	)

	// Reset the selinuxprofile for further recordings
	if _, err := enricherClient.ResetAvcs(ctx, request); err != nil {
		return errors.Wrapf(
			err, "reset selinuxprofile for profile %s", profileName,
		)
	}

	return nil
}

func (r *RecorderReconciler) formatSelinuxProfile(
	selinuxprofile *selxv1alpha2.SelinuxProfile,
	avcResponse *enricherapi.AvcResponse,
) (selxv1alpha2.Allow, error) {
	seBuilder := newSeProfileBuilder(selinuxprofile.GetPolicyUsage(), r.log)

	if err := seBuilder.AddAvcList(avcResponse.GetAvc()); err != nil {
		return nil, errors.Wrap(err, "consuming AVCs")
	}

	sePol, err := seBuilder.Format()
	if err != nil {
		return nil, errors.Wrap(err, "building policy")
	}

	return sePol, nil
}

func (r *RecorderReconciler) collectBpfProfiles(
	ctx context.Context,
	name types.NamespacedName,
	profiles []profileToCollect,
) error {
	recorderClient, cancel, err := r.getBpfRecorderClient()
	if err != nil {
		return errors.Wrap(err, "get bpf recorder client")
	}
	defer cancel()

	for _, profile := range profiles {
		r.log.Info("Collecting BPF profile", "name", profile.name, "kind", profile.kind)
		response, err := recorderClient.SyscallsForProfile(
			ctx, &bpfrecorderapi.ProfileRequest{Name: profile.name},
		)
		if err != nil {
			// Something went wrong during BPF event collection, which also
			// means that we do not have to retry this failure case.
			if status.Convert(err).Message() == bpfrecorder.ErrNotFound.Error() {
				r.log.Error(err, "Recorded profile not found, giving up")
				if err := r.stopBpfRecorder(); err != nil {
					r.log.Error(err, "Unable to stop bpf recorder")
				}
				return nil
			}
			return errors.Wrap(err, "get syscalls for profile")
		}

		arch, err := goArchToSeccompArch(response.GoArch)
		if err != nil {
			return errors.Wrap(err, "get seccomp arch")
		}

		profileSpec := seccompprofileapi.SeccompProfileSpec{
			DefaultAction: seccomp.ActErrno,
			Architectures: []seccompprofileapi.Arch{arch},
			Syscalls: []*seccompprofileapi.Syscall{{
				Action: seccomp.ActAllow,
				Names:  response.GetSyscalls(),
			}},
		}

		// Remove the timestamp
		profileName, err := extractProfileName(profile.name)
		if err != nil {
			return errors.Wrap(err, "extract profile name")
		}

		profile := &seccompprofileapi.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      profileName,
				Namespace: name.Namespace,
			},
			Spec: profileSpec,
		}

		res, err := controllerutil.CreateOrUpdate(ctx, r.client, profile,
			func() error {
				profile.Spec = profileSpec
				return nil
			},
		)
		if err != nil {
			r.log.Error(err, "Cannot create seccompprofile resource")
			r.record.Event(profile, event.Warning(reasonProfileCreationFailed, err))
			return errors.Wrap(err, "create seccompProfile resource")
		}

		r.log.Info("Created/updated profile", "action", res, "name", profileName)
		r.record.Event(
			profile,
			event.Normal(reasonProfileCreated, "seccomp profile created"),
		)
	}

	if err := r.stopBpfRecorder(); err != nil {
		r.log.Error(err, "Unable to stop bpf recorder")
		return errors.Wrap(err, "stop bpf recorder")
	}
	return nil
}

func extractProfileName(s string) (string, error) {
	lastIndex := strings.LastIndex(s, "-")
	if lastIndex == -1 {
		return "", errors.Errorf("malformed profile path: %s", s)
	}
	return s[:lastIndex], nil
}

// parseHookAnnotations parses the provided annotations and extracts the
// mandatory output files for the hook recorder.
func parseHookAnnotations(annotations map[string]string) (res []profileToCollect, err error) {
	const prefix = "of:"

	for key, value := range annotations {
		if !strings.HasPrefix(key, config.SeccompProfileRecordHookAnnotationKey) {
			continue
		}

		if !strings.HasPrefix(value, prefix) {
			return nil, errors.Wrapf(errors.New(errInvalidAnnotation),
				"must start with %q prefix", prefix)
		}

		outputFile := strings.TrimSpace(strings.TrimPrefix(value, prefix))
		if !filepath.IsAbs(outputFile) {
			return nil, errors.Wrapf(errors.New(errInvalidAnnotation),
				"output file path must be absolute: %q", outputFile)
		}

		if outputFile == "" {
			return nil, errors.Wrap(errors.New(errInvalidAnnotation),
				"providing output file is mandatory")
		}
		if !strings.HasPrefix(outputFile, config.ProfileRecordingOutputPath) {
			// Ignoring profile outside standard output path, it may be
			// user-defined
			continue
		}

		res = append(res, profileToCollect{
			kind: profilerecording1alpha1.ProfileRecordingKindSeccompProfile,
			name: outputFile,
		})
	}

	return res, nil
}

// parseLogAnnotations parses the provided annotations and extracts the
// mandatory output profiles for the log recorder.
func parseLogAnnotations(annotations map[string]string) (res []profileToCollect, err error) {
	for key, profile := range annotations {
		var collectProfile profileToCollect

		// nolint: gocritic
		if strings.HasPrefix(key, config.SeccompProfileRecordLogsAnnotationKey) {
			collectProfile.kind = profilerecording1alpha1.ProfileRecordingKindSeccompProfile
		} else if strings.HasPrefix(key, config.SelinuxProfileRecordLogsAnnotationKey) {
			collectProfile.kind = profilerecording1alpha1.ProfileRecordingKindSelinuxProfile
		} else {
			continue
		}

		if profile == "" {
			return nil, errors.Wrap(errors.New(errInvalidAnnotation),
				"providing output profile is mandatory")
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

		if strings.HasPrefix(key, config.SeccompProfileRecordBpfAnnotationKey) {
			collectProfile.kind = profilerecording1alpha1.ProfileRecordingKindSeccompProfile
		} else {
			continue
		}

		if profile == "" {
			return nil, errors.Wrap(errors.New(errInvalidAnnotation),
				"providing output profile is mandatory")
		}
		collectProfile.name = profile

		res = append(res, collectProfile)
	}

	return res, nil
}

type seProfileBuilder struct {
	permMap       map[string]sets.String
	usageCtx      string
	policyBuilder selxv1alpha2.Allow
	log           logr.Logger
	// used to optimize sorting
	keys []string
}

func newSeProfileBuilder(usageCtx string, log logr.Logger) *seProfileBuilder {
	return &seProfileBuilder{
		permMap:       make(map[string]sets.String),
		usageCtx:      usageCtx,
		policyBuilder: make(selxv1alpha2.Allow),
		log:           log,
		keys:          make([]string, 0),
	}
}

func (sb *seProfileBuilder) AddAvcList(avcs []*enricherapi.AvcResponse_SelinuxAvc) error {
	for _, avc := range avcs {
		sb.log.Info("Received an AVC response",
			"perm", avc.Perm, "tclass",
			avc.Tclass, "scontext", avc.Scontext,
			"tcontext", avc.Tcontext)

		if err := sb.addAvc(avc); err != nil {
			return errors.Wrap(err, "adding AVC")
		}
	}

	return nil
}

func (sb *seProfileBuilder) addAvc(avc *enricherapi.AvcResponse_SelinuxAvc) error {
	ctxType, err := ctxt2type(avc.Tcontext)
	if err != nil {
		return errors.Wrap(err, "converting context to type")
	}

	key := avc.Tclass + " " + ctxType
	sb.keys = append(sb.keys, key)

	perms, ok := sb.permMap[key]
	if ok {
		perms.Insert(avc.Perm)
	} else {
		sb.permMap[key] = sets.NewString(avc.Perm)
	}
	return nil
}

func (sb *seProfileBuilder) Format() (selxv1alpha2.Allow, error) {
	sort.Strings(sb.keys)
	for _, key := range sb.keys {
		val := sb.permMap[key]
		if err := sb.writeLineFromKeyVal(key, val); err != nil {
			return nil, errors.Wrap(err, "writing policy line from key-value pair")
		}
	}

	return sb.policyBuilder, nil
}

func (sb *seProfileBuilder) writeLineFromKeyVal(key string, val sets.String) error {
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
	l := val.List()
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
		return "", errors.New("Malformed SELinux context")
	}
	return elems[2], nil
}

func goArchToSeccompArch(goarch string) (seccompprofileapi.Arch, error) {
	seccompArch, err := seccomp.GoArchToSeccompArch(goarch)
	if err != nil {
		return "", errors.Wrap(err, "convert golang to seccomp arch")
	}
	return seccompprofileapi.Arch(seccompArch), nil
}
