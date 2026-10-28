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

package recordingtracker

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/common"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/recordingkinds"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// conflictProfilesShown is how many conflicting profiles the
	// ProfileConflict condition names.
	conflictProfilesShown = 5
)

// recordingStatusReconciler reports on the conditions of a ProfileRecording
// whether it can record and whether profiles which it would write belong to
// somebody else. The recording webhook skips invalid recordings and the
// profile recorder of the daemon drops the data it cannot store, so this is
// the only place where the user can see it.
type recordingStatusReconciler struct {
	client client.Client
	reader client.Reader
	log    logr.Logger

	// operatorNamespace holds the SecurityProfilesOperatorDaemons. The
	// recorders and SELinux are not checked without it.
	operatorNamespace string
	// isOpenShift is true on OpenShift, where SELinux is enabled unless the
	// SecurityProfilesOperatorDaemon disables it.
	isOpenShift bool
	// env holds the recorders which the environment of the operator enables
	// in addition to the SecurityProfilesOperatorDaemons.
	env recorderEnv
}

// recorderEnv holds the recorders which the environment of the operator
// enables. The manager passes these variables on to the daemon.
type recorderEnv struct {
	logEnricher bool
	bpfRecorder bool
}

// recorderEnvFromEnvironment reads the recorders which the environment of the
// operator enables. Values which are not a boolean do not enable them.
func recorderEnvFromEnvironment() recorderEnv {
	return recorderEnv{
		logEnricher: config.EnvEnabled(config.EnableLogEnricherEnvKey),
		bpfRecorder: config.EnvEnabled(config.EnableBpfRecorderEnvKey),
	}
}

func (r *recordingStatusReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	// The SPOD, webhook and namespace events reconcile every recording, so the
	// first attempt reads the recording from the cache. A retry after a
	// conflict reads it from the API server, the cache may still return the
	// version which lost.
	return reconcile.Result{}, util.RetryWithFreshReads(
		ctx,
		r.client,
		r.reader,
		func(c client.Client) error {
			recording := &profilerecordingapi.ProfileRecording{}
			if err := c.Get(ctx, req.NamespacedName, recording); err != nil {
				return client.IgnoreNotFound(err)
			}

			ready, err := r.readyCondition(ctx, recording)
			if err != nil {
				return err
			}

			conflict, err := r.conflictCondition(ctx, recording)
			if err != nil {
				return err
			}

			updated := recording.DeepCopy()
			updated.Status.SetConditionForGeneration(&ready, recording.GetGeneration())
			updated.Status.SetConditionForGeneration(&conflict, recording.GetGeneration())

			if reflect.DeepEqual(recording.Status, updated.Status) {
				return nil
			}

			r.log.V(config.VerboseLevel).
				Info("Updating recording conditions", "recording", req.NamespacedName,
					"reason", ready.Reason, "conflict", conflict.Reason)

			if err := c.Status().Update(ctx, updated); err != nil {
				return fmt.Errorf("updating recording status: %w", err)
			}

			return nil
		},
		errors.IsConflict,
	)
}

// readyCondition returns the Ready condition of the recording.
func (r *recordingStatusReconciler) readyCondition(
	ctx context.Context, recording *profilerecordingapi.ProfileRecording,
) (metav1.Condition, error) {
	if err := recording.ValidateRecorderKindCombination(); err != nil {
		return common.Unavailable(err.Error()), nil
	}

	// The recording webhook skips a recording with an invalid selector for
	// every pod.
	if _, err := metav1.LabelSelectorAsSelector(recording.Spec.PodSelector); err != nil {
		return notReady(profilerecordingapi.ReasonInvalidPodSelector, fmt.Sprintf(
			"the podSelector is invalid, so no pod gets recorded: %v", err,
		)), nil
	}

	// Only an unset list selects every container, see util.RecordsContainer.
	if recording.Spec.Containers != nil && len(recording.Spec.Containers) == 0 {
		return notReady(profilerecordingapi.ReasonNoContainersSelected,
			"spec.containers is an empty list, so no container gets recorded, "+
				"remove the field to record every container",
		), nil
	}

	enabled, field, err := r.recorderEnabled(ctx, recording.Spec.Recorder)
	if err != nil {
		return metav1.Condition{}, err
	}

	if !enabled {
		return notReady(profilerecordingapi.ReasonRecorderDisabled, fmt.Sprintf(
			"the %s recorder is not enabled, set spec.enricher.%s of the SecurityProfilesOperatorDaemon",
			recording.Spec.Recorder,
			field,
		)), nil
	}

	if recording.Spec.Kind == profilerecordingapi.ProfileRecordingKindSelinuxProfile {
		selinux, err := r.selinuxEnabled(ctx)
		if err != nil {
			return metav1.Condition{}, err
		}

		if !selinux {
			return notReady(profilerecordingapi.ReasonSelinuxDisabled,
				"SELinux is not enabled, so the nodes do not install the SELinux type which "+
					"the recorded containers get and they fail to start, "+
					"set spec.selinux.enable of the SecurityProfilesOperatorDaemon",
			), nil
		}
	}

	selected, err := r.namespaceSelected(ctx, recording.GetNamespace())
	if err != nil {
		return metav1.Condition{}, err
	}

	if !selected {
		return notReady(profilerecordingapi.ReasonNamespaceNotEnabled, fmt.Sprintf(
			"the recording webhook does not select the namespace %s, "+
				"by default namespaces need the %s label",
			recording.GetNamespace(), bindata.EnableRecordingLabel,
		)), nil
	}

	return common.Available(), nil
}

// notReady returns a false Ready condition with the reason and message.
func notReady(reason common.ConditionReason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               string(common.TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(reason),
		Message:            message,
	}
}

// recorderEnabled returns whether the recorder is enabled, and the field of
// the SecurityProfilesOperatorDaemon which enables it. The daemons only follow
// the SecurityProfilesOperatorDaemon named spod, the others are not
// reconciled. Without it nothing can be told, and the recorder counts as
// enabled.
func (r *recordingStatusReconciler) recorderEnabled(
	ctx context.Context, recorder profilerecordingapi.ProfileRecorder,
) (enabled bool, field string, err error) {
	var enables func(*spodapi.SPODEnricherConfig) *bool

	switch recorder {
	case profilerecordingapi.ProfileRecorderLogs:
		if r.env.logEnricher {
			return true, "", nil
		}

		field = "enableLogEnricher"
		enables = func(c *spodapi.SPODEnricherConfig) *bool { return c.EnableLogEnricher }
	case profilerecordingapi.ProfileRecorderBpf:
		if r.env.bpfRecorder {
			return true, "", nil
		}

		field = "enableBpfRecorder"
		enables = func(c *spodapi.SPODEnricherConfig) *bool { return c.EnableBpfRecorder }
	default:
		return true, "", nil
	}

	if r.operatorNamespace == "" {
		return true, "", nil
	}

	spod := &spodapi.SecurityProfilesOperatorDaemon{}
	if err := r.client.Get(
		ctx, client.ObjectKey{Name: config.SPOdName, Namespace: r.operatorNamespace}, spod,
	); err != nil {
		if errors.IsNotFound(err) {
			return true, "", nil
		}

		return false, "", fmt.Errorf("getting SecurityProfilesOperatorDaemon: %w", err)
	}

	if ptr.Deref(enables(&spod.Spec.Enricher), false) {
		return true, "", nil
	}

	return false, field, nil
}

// selinuxEnabled returns whether the SecurityProfilesOperatorDaemon enables
// SELinux, so that the selinuxd container installs the SELinux type of the
// recorded containers. Without the operator namespace or the
// SecurityProfilesOperatorDaemon nothing can be told, and it counts as
// enabled.
func (r *recordingStatusReconciler) selinuxEnabled(ctx context.Context) (bool, error) {
	if r.operatorNamespace == "" {
		return true, nil
	}

	enabled, err := bindata.ProfileKindEnabled(
		profilebindingapi.ProfileBindingKindSelinuxProfile,
		r.isOpenShift,
		func() (*spodapi.SecurityProfilesOperatorDaemon, error) {
			spod := &spodapi.SecurityProfilesOperatorDaemon{}

			return spod, r.client.Get(
				ctx, client.ObjectKey{Name: config.SPOdName, Namespace: r.operatorNamespace}, spod,
			)
		},
	)
	if err != nil {
		return false, fmt.Errorf("getting SecurityProfilesOperatorDaemon: %w", err)
	}

	return enabled, nil
}

// namespaceSelected returns whether the recording webhook selects the
// namespace, see bindata.RecordingWebhookSelectsNamespace.
func (r *recordingStatusReconciler) namespaceSelected(
	ctx context.Context, namespace string,
) (bool, error) {
	return bindata.RecordingWebhookSelectsNamespace(ctx, r.client, namespace)
}

// conflictCondition returns the ProfileConflict condition of the recording.
// It names the profiles which the recording would write, but which exist
// already and were recorded by another recording or not recorded at all. The
// profile recorder and the merger drop the data for those.
func (r *recordingStatusReconciler) conflictCondition(
	ctx context.Context, recording *profilerecordingapi.ProfileRecording,
) (metav1.Condition, error) {
	condition := metav1.Condition{
		Type:               string(profilerecordingapi.ConditionTypeProfileConflict),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(profilerecordingapi.ReasonNoProfileConflict),
	}

	kind, ok := recordingkinds.Of(recording.Spec.Kind)
	if !ok {
		return condition, nil
	}

	names, err := r.recordedProfileNames(ctx, recording, kind)
	if err != nil {
		return metav1.Condition{}, err
	}

	var conflicts []string

	for _, name := range names {
		prf := kind.NewObject()
		if err := r.client.Get(ctx, client.ObjectKey{Name: name}, prf); err != nil {
			if errors.IsNotFound(err) {
				continue
			}

			return metav1.Condition{}, fmt.Errorf("getting profile %s: %w", name, err)
		}

		if util.CheckRecordingOwner(prf, recording.GetName(), recording.GetNamespace()) != nil {
			conflicts = append(conflicts, name)
		}
	}

	if len(conflicts) == 0 {
		return condition, nil
	}

	condition.Status = metav1.ConditionTrue
	condition.Reason = string(profilerecordingapi.ReasonProfileOwnedByOther)
	condition.Message = fmt.Sprintf(
		"the recorded data for these %s profiles gets dropped, because they exist already "+
			"and were recorded by another recording or not recorded at all: %s",
		recording.Spec.Kind, shortList(conflicts),
	)

	return condition, nil
}

// shortList joins the first sorted names.
func shortList(names []string) string {
	if len(names) <= conflictProfilesShown {
		return strings.Join(names, ", ")
	}

	return fmt.Sprintf("%s and %d more",
		strings.Join(names[:conflictProfilesShown], ", "), len(names)-conflictProfilesShown)
}

// recordedProfileNames returns the sorted names of the profiles which the
// recording writes, as far as they can be told: the profiles of the recorded
// containers of the tracked pods, and the merged profiles of the containers
// which the recording selects and of its partial profiles. The profiles of
// pods which are not tracked yet are not known. They are named like the
// profile recorder of the daemon and the merger name them.
func (r *recordingStatusReconciler) recordedProfileNames(
	ctx context.Context, recording *profilerecordingapi.ProfileRecording, kind recordingkinds.Kind,
) ([]string, error) {
	names := sets.New[string]()
	merge := recording.Spec.MergeStrategy == profilerecordingapi.ProfileMergeContainers

	if merge {
		for _, ctr := range recording.Spec.Containers {
			names.Insert(util.RecordedProfileName(recording.GetName(), ctr, ""))
		}
	}

	for _, podName := range recording.Status.ActiveWorkloads {
		// The pod is only read, so the cached one is not copied.
		pod := &corev1.Pod{}
		if err := r.client.Get(
			ctx, client.ObjectKey{Name: podName, Namespace: recording.GetNamespace()}, pod,
			client.UnsafeDisableDeepCopy,
		); err != nil {
			if errors.IsNotFound(err) {
				continue
			}

			return nil, fmt.Errorf("getting pod %s: %w", podName, err)
		}

		// Pods of a replicating controller get the suffix of their
		// generated name, see the profile recorder.
		replicaSuffix := ""
		if pod.GenerateName != "" && pod.GetName() != pod.GenerateName &&
			strings.HasPrefix(pod.GetName(), pod.GenerateName) {
			replicaSuffix = strings.TrimPrefix(pod.GetName(), pod.GenerateName)
		}

		for _, ctr := range annotatedContainers(pod, recording.GetName(), false) {
			if !merge {
				names.Insert(util.RecordedProfileName(recording.GetName(), ctr, replicaSuffix))

				continue
			}

			partialSuffix := replicaSuffix
			if partialSuffix == "" {
				partialSuffix = pod.GetName()
			}

			names.Insert(
				util.RecordedProfileName(recording.GetName(), ctr, partialSuffix),
				util.RecordedProfileName(recording.GetName(), ctr, ""),
			)
		}
	}

	// The partial profiles get merged into the profile of their container,
	// also if the merge strategy changed since. Only their labels are read,
	// so they are not copied.
	partials := kind.NewList()
	if err := r.client.List(ctx, partials, client.MatchingLabels{
		profilerecordingapi.ProfileToRecordingLabel:          recording.GetName(),
		profilerecordingapi.ProfileToRecordingNamespaceLabel: recording.GetNamespace(),
		profilebase.ProfilePartialLabel:                      "true",
	}, client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("listing partial profiles: %w", err)
	}

	if err := meta.EachListItem(partials, func(obj runtime.Object) error {
		prf, ok := obj.(client.Object)
		if !ok {
			return fmt.Errorf("object %T is not a client.Object", obj)
		}

		if ctr := prf.GetLabels()[profilerecordingapi.ProfileToContainerLabel]; ctr != "" {
			names.Insert(util.RecordedProfileName(recording.GetName(), ctr, ""))
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return sets.List(names), nil
}

// admissionClockSkew is how much later than the creation of a pod the time in
// a recording annotation may be, which the recording webhook set while it
// admitted the pod. It covers the clocks of the webhook and the API server
// which differ.
const admissionClockSkew = time.Minute

// annotatedContainers returns the sorted names of the containers of the pod
// which carry a recording annotation of the recording, of any kind and
// recorder. The annotation values have the form
// "<recording>_<container>_<nonce>_<unix time>", the underscore is not valid
// in object names. With admitted, only the annotations of existing containers
// count which the recording webhook set while it admitted the pod: the webhook
// takes the time before the API server stores the pod and sets its creation
// timestamp, while an annotation added by a later update gets a later time.
func annotatedContainers(pod *corev1.Pod, recordingName string, admitted bool) []string {
	var containers []string

	for key, value := range pod.GetAnnotations() {
		ctr, ok := bindata.RecordingAnnotationContainer(key)
		if !ok {
			continue
		}

		rest, ok := strings.CutPrefix(value, recordingName+"_"+ctr+"_")
		if !ok || (admitted && !admittedAnnotation(pod, ctr, rest)) {
			continue
		}

		containers = append(containers, ctr)
	}

	slices.Sort(containers)

	return slices.Compact(containers)
}

// admittedAnnotation returns true if the container exists and the rest of the
// annotation value, "<nonce>_<unix time>", has a time which is not later than
// the creation of the pod, see annotatedContainers.
func admittedAnnotation(pod *corev1.Pod, ctr, rest string) bool {
	_, timestamp, ok := strings.Cut(rest, "_")
	if !ok || pod.CreationTimestamp.IsZero() {
		return false
	}

	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}

	exists := slices.ContainsFunc(util.PodContainers(pod), func(c *corev1.Container) bool {
		return c.Name == ctr
	})

	return exists && !time.Unix(seconds, 0).After(pod.CreationTimestamp.Add(admissionClockSkew))
}

// recordedContainers returns the names of the init and regular containers of
// the pod which the recording selects now, and which carry the annotation of
// the kind and recorder of the recording, like the daemon checks it when a
// container starts. It tells whether a pod gets tracked anew whose annotation
// the recording webhook did not set while it admitted the pod, see
// podRecordedBy.
func recordedContainers(pod *corev1.Pod, recording *profilerecordingapi.ProfileRecording) []string {
	selector, err := metav1.LabelSelectorAsSelector(recording.Spec.PodSelector)
	if err != nil || !selector.Matches(labels.Set(pod.GetLabels())) {
		return nil
	}

	var containers []string

	for _, ctr := range util.PodContainers(pod) {
		if !util.RecordsContainer(recording, ctr.Name) {
			continue
		}

		key, _, err := recording.CtrAnnotation(ctr.Name)
		if err != nil {
			return nil
		}

		if strings.HasPrefix(pod.GetAnnotations()[key], recording.GetName()+"_"+ctr.Name+"_") {
			containers = append(containers, ctr.Name)
		}
	}

	return containers
}
