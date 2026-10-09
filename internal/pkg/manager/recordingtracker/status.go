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
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/api/common"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
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
	// recorders are not checked without it.
	operatorNamespace string
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
	envBool := func(key string) bool {
		value, err := strconv.ParseBool(os.Getenv(key))

		return err == nil && value
	}

	return recorderEnv{
		logEnricher: envBool(config.EnableLogEnricherEnvKey),
		bpfRecorder: envBool(config.EnableBpfRecorderEnvKey),
	}
}

func (r *recordingStatusReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	return reconcile.Result{}, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		recording := &profilerecordingapi.ProfileRecording{}
		if err := r.reader.Get(ctx, req.NamespacedName, recording); err != nil {
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

		if err := r.client.Status().Update(ctx, updated); err != nil {
			return fmt.Errorf("updating recording status: %w", err)
		}

		return nil
	})
}

// readyCondition returns the Ready condition of the recording.
func (r *recordingStatusReconciler) readyCondition(
	ctx context.Context, recording *profilerecordingapi.ProfileRecording,
) (metav1.Condition, error) {
	if err := recording.ValidateRecorderKindCombination(); err != nil {
		return common.Unavailable(err.Error()), nil
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

// namespaceSelected returns whether the recording webhook selects the
// namespace, see bindata.WebhookSelectsNamespace.
func (r *recordingStatusReconciler) namespaceSelected(
	ctx context.Context, namespace string,
) (bool, error) {
	return bindata.WebhookSelectsNamespace(ctx, r.client, bindata.RecordingWebhookName, namespace)
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

	kind, ok := profileKinds[recording.Spec.Kind]
	if !ok {
		return condition, nil
	}

	names, err := r.recordedProfileNames(ctx, recording, kind)
	if err != nil {
		return metav1.Condition{}, err
	}

	var conflicts []string

	for _, name := range names {
		prf := kind.newObject()
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

// profileKind is a kind of profiles which a recording records.
type profileKind struct {
	newObject func() client.Object
	newList   func() client.ObjectList
}

// profileKinds are the kinds of profiles which the recordings record.
var profileKinds = map[profilerecordingapi.ProfileRecordingKind]profileKind{
	profilerecordingapi.ProfileRecordingKindSeccompProfile: {
		newObject: func() client.Object { return &seccompprofileapi.SeccompProfile{} },
		newList:   func() client.ObjectList { return &seccompprofileapi.SeccompProfileList{} },
	},
	profilerecordingapi.ProfileRecordingKindSelinuxProfile: {
		newObject: func() client.Object { return &selinuxprofileapi.SelinuxProfile{} },
		newList:   func() client.ObjectList { return &selinuxprofileapi.SelinuxProfileList{} },
	},
	profilerecordingapi.ProfileRecordingKindAppArmorProfile: {
		newObject: func() client.Object { return &apparmorprofileapi.AppArmorProfile{} },
		newList:   func() client.ObjectList { return &apparmorprofileapi.AppArmorProfileList{} },
	},
}

// recordedProfileNames returns the sorted names of the profiles which the
// recording writes, as far as they can be told: the profiles of the recorded
// containers of the tracked pods, and the merged profiles of the containers
// which the recording selects and of its partial profiles. The profiles of
// pods which are not tracked yet are not known. They are named like the
// profile recorder of the daemon and the merger name them.
func (r *recordingStatusReconciler) recordedProfileNames(
	ctx context.Context, recording *profilerecordingapi.ProfileRecording, kind profileKind,
) ([]string, error) {
	names := sets.New[string]()
	merge := recording.Spec.MergeStrategy == profilerecordingapi.ProfileMergeContainers

	if merge {
		for _, ctr := range recording.Spec.Containers {
			names.Insert(util.RecordedProfileName(recording.GetName(), ctr, ""))
		}
	}

	for _, podName := range recording.Status.ActiveWorkloads {
		pod := &corev1.Pod{}
		if err := r.client.Get(
			ctx, client.ObjectKey{Name: podName, Namespace: recording.GetNamespace()}, pod,
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

		for _, ctr := range recordedContainers(pod, recording.GetName()) {
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
	// also if the merge strategy changed since.
	partials := kind.newList()
	if err := r.client.List(ctx, partials, client.MatchingLabels{
		profilerecordingapi.ProfileToRecordingLabel:          recording.GetName(),
		profilerecordingapi.ProfileToRecordingNamespaceLabel: recording.GetNamespace(),
		profilebase.ProfilePartialLabel:                      "true",
	}); err != nil {
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

// recordedContainers returns the names of the containers of the pod which
// the recording webhook annotated for the recording. The annotation values
// start with the recording name followed by an underscore, which is not valid
// in object names.
func recordedContainers(pod *corev1.Pod, recordingName string) []string {
	var containers []string

	for key, value := range pod.GetAnnotations() {
		for _, prefix := range recordingAnnotationKeys {
			if strings.HasPrefix(key, prefix) && strings.HasPrefix(value, recordingName+"_") {
				containers = append(containers, strings.TrimPrefix(key, prefix))
			}
		}
	}

	return containers
}
