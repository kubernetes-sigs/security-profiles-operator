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

package bindata

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// DefaultLogEnricherProfile returns the default seccomp profile for log enricher.
// Seccomp profiles are cluster scoped, so it has no namespace.
func DefaultLogEnricherProfile() *seccompprofileapi.SeccompProfile {
	labels := map[string]string{labelApp: config.OperatorName}

	return &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:   config.LogEnricherProfile,
			Labels: labels,
		},
		Spec: seccompprofileapi.SeccompProfileSpec{
			DefaultAction: seccompprofileapi.ActLog,
		},
	}
}

// UsesLogEnricherProfile returns true if the recording webhook sets the log
// enricher profile on the containers which the recording records.
func UsesLogEnricherProfile(pr *profilerecordingapi.ProfileRecording) bool {
	return pr.Spec.Recorder == profilerecordingapi.ProfileRecorderLogs &&
		pr.Spec.Kind == profilerecordingapi.ProfileRecordingKindSeccompProfile
}

// LogEnricherProfileState is the state of the log enricher profile, which the
// recording webhook and the recording conditions check.
type LogEnricherProfileState int

const (
	// LogEnricherProfileAvailable means that the profile exists and is not
	// being deleted.
	LogEnricherProfileAvailable LogEnricherProfileState = iota
	// LogEnricherProfileMissing means that the profile does not exist. The
	// operator only creates it once the log enricher has been enabled, and
	// deletes it if the allow lists of the SPOD reject it.
	LogEnricherProfileMissing
	// LogEnricherProfileDeleting means that the profile is being deleted.
	LogEnricherProfileDeleting
	// LogEnricherProfileWithoutStatus means that no node reported a status
	// for the profile yet, like the binding webhook rejects such profiles.
	LogEnricherProfileWithoutStatus
)

// GetLogEnricherProfileState returns the state of the log enricher profile,
// which get reads. A container which references a missing localhost profile
// cannot start, so the recordings which would set it do not record the pods
// unless it is available. A profile without status, which no node installed
// yet, counts as not available. Pending, InProgress or Error do: the kubelet
// retries a container whose localhost profile file is missing, and an
// aggregated Error of a single node would otherwise skip the recordings on
// every node.
func GetLogEnricherProfileState(
	ctx context.Context,
	get func(context.Context, client.ObjectKey) (*seccompprofileapi.SeccompProfile, error),
) (LogEnricherProfileState, error) {
	profile, err := get(ctx, client.ObjectKey{Name: config.LogEnricherProfile})
	if err != nil {
		if errors.IsNotFound(err) {
			return LogEnricherProfileMissing, nil
		}

		return LogEnricherProfileMissing, fmt.Errorf("getting the log enricher profile: %w", err)
	}

	if !profile.GetDeletionTimestamp().IsZero() {
		return LogEnricherProfileDeleting, nil
	}

	if profile.Status.Status == "" {
		return LogEnricherProfileWithoutStatus, nil
	}

	return LogEnricherProfileAvailable, nil
}

// SeccompProfileGetter returns a function which reads a seccomp profile with
// the client, for GetLogEnricherProfileState.
func SeccompProfileGetter(
	c client.Reader,
) func(context.Context, client.ObjectKey) (*seccompprofileapi.SeccompProfile, error) {
	return func(ctx context.Context, key client.ObjectKey) (*seccompprofileapi.SeccompProfile, error) {
		profile := &seccompprofileapi.SeccompProfile{}
		if err := c.Get(ctx, key, profile); err != nil {
			return nil, err
		}

		return profile, nil
	}
}
