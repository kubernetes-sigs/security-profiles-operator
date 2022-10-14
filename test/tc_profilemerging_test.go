/*
Copyright 2022 The Kubernetes Authors.

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

package e2e_test

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
)

const (
	containerName             = "nginx"
	mergeProfileRecordingName = "test-profile-merging"
	profileRecordingTemplate  = `
    apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
    kind: ProfileRecording
    metadata:
      name: %s
    spec:
      kind: %s
      recorder: %s
      mergeStrategy: %s
      podSelector:
        matchLabels:
          %s: %s
`
)

func (e *e2e) testSeccompBpfProfileMerging() {
	e.bpfRecorderOnlyTestCase()
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileMergingTest(
		"bpf",
		"SeccompProfile", "sp",
		"/bin/mknod /tmp/foo p",
		"listen",
		"mknod\n", // for some reason bpf recording always allows mknodat(), let's explicitly check mknod()
		regexp.MustCompile(
			`(?s)"container"="nginx".*"syscallName"="listen"`+
				`.*"container"="nginx".*"syscallName"="listen"`))
}

func (e *e2e) testSeccompLogsProfileMerging() {
	e.logEnricherOnlyTestCase()
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileMergingTest(
		"logs",
		"SeccompProfile", "sp",
		"/bin/mknod /tmp/foo p",
		"listen", "mknod",
		regexp.MustCompile(
			`(?s)"container"="nginx".*"syscallName"="listen"`+
				`.*"container"="nginx".*"syscallName"="listen"`))
}

func (e *e2e) testSelinuxLogsProfileMerging() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileMergingTest(
		"logs",
		"SelinuxProfile", "selinuxprofile",
		"curl localhost:8080",
		"name_bind", "name_connect",
		regexp.MustCompile(`(?s)"perm"="listen"`+
			`.*"perm"="listen"`),
	)
}

func (e *e2e) profileMergingTest(
	recordedMethod, recorderKind, resource, trigger, commonAction, triggeredAction string,
	conditions ...*regexp.Regexp,
) {
	e.logf("Creating a profile recording with merge strategy 'containers'")
	deleteManifestFn := createTemplatedProfileRecording(e, profileRecTmplMetadata{
		name:          mergeProfileRecordingName,
		recorderKind:  recorderKind,
		recorder:      recordedMethod,
		mergeStrategy: "containers",
		labelKey:      "app",
		labelValue:    "alpine",
	})
	defer deleteManifestFn()

	since, deployName := e.createRecordingTestDeployment()
	suffixes := e.getPodSuffixesByLabel("app=alpine")
	if recordedMethod == "logs" {
		e.waitForEnricherLogs(since, conditions...)
	} else if recordedMethod == "bpf" {
		profileNames := make([]string, 0)
		for _, sfx := range suffixes {
			profileNames = append(profileNames, mergeProfileRecordingName+"-"+containerName+"-"+sfx)
		}
		e.waitForBpfRecorderLogs(since, profileNames...)
	} else {
		e.Failf("unknown recorded method %s", recordedMethod)
	}

	podNamesString := e.kubectl("get", "pods", "-l", "app=alpine", "-o", "jsonpath={.items[*].metadata.name}")
	onePodName := strings.Fields(podNamesString)[0]
	e.kubectl(
		"exec", onePodName, "--", "bash", "-c", trigger,
	)

	e.kubectl("delete", "deploy", deployName)

	// check that the policies are partial
	for _, sfx := range suffixes {
		recordedProfileName := mergeProfileRecordingName + "-" + containerName + "-" + sfx
		e.logf("Checking that the recorded profile %s is partial", recordedProfileName)

		profile := e.retryGetProfile(resource, recordedProfileName)
		e.Contains(profile, v1alpha1.ProfilePartialLabel)
		e.Contains(profile, commonAction)

		if strings.HasSuffix(onePodName, sfx) {
			// check the policy from the first container, it should contain the triggered action
			e.Contains(profile, triggeredAction)
		} else {
			// the others should not
			e.NotContains(profile, triggeredAction)
		}
	}

	// delete the recording, this triggers the merge
	e.kubectl("delete", "profilerecording", mergeProfileRecordingName)

	// the partial policies should be gone, instead one policy should be created. Retry a couple of times
	// because removing the partial policies is not atomic. In prod you'd probably list the profiles
	// and check the absence of the partial label.
	policiesRecorded := make([]string, 0)
	mergedProfileName := fmt.Sprintf("%s-%s", mergeProfileRecordingName, containerName)
	for i := 0; i < 3; i++ {
		policiesRecordedString := e.kubectl("get", resource,
			"-l", "spo.x-k8s.io/recording-id="+mergeProfileRecordingName,
			"-o", "jsonpath={.items[*].metadata.name}")
		policiesRecorded = strings.Fields(policiesRecordedString)
		if len(policiesRecorded) > 1 {
			time.Sleep(5 * time.Second)
			continue
		}
	}
	e.Len(policiesRecorded, 1)
	e.Equal(mergedProfileName, policiesRecorded[0])

	// the result should contain the triggered action
	mergedProfile := e.retryGetProfile(resource, mergedProfileName)
	e.Contains(mergedProfile, triggeredAction)
	e.Contains(mergedProfile, commonAction)
	e.kubectl("delete", resource, mergedProfileName)
}

type profileRecTmplMetadata struct {
	name, recorderKind, recorder, mergeStrategy, labelKey, labelValue string
}

func createTemplatedProfileRecording(e *e2e, metadata profileRecTmplMetadata) func() {
	manifest := fmt.Sprintf(profileRecordingTemplate,
		metadata.name, metadata.recorderKind, metadata.recorder,
		metadata.mergeStrategy, metadata.labelKey, metadata.labelValue)
	deleteFn := e.writeAndCreate(manifest, fmt.Sprintf("%s.yml", metadata.name))
	return deleteFn
}
